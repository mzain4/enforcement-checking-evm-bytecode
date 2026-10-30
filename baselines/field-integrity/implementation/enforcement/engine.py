"""Bounded symbolic execution of supported Gigahorse TAC for enforcement obligations.

This is an experimental abstraction, not an EVM equivalence proof. Unknown operations,
ambiguous control flow and exhausted bounds are retained. Policies contain protocol
requirements/ABI context, not vulnerability labels. No original detector code is imported.
"""
from dataclasses import dataclass, field, replace
from collections import Counter
import hashlib
import time
import z3 as z
from .facts import Facts

B=z.BitVecSort(256); BYTE=z.BitVecSort(8); MASK=(1<<256)-1
def bv(value):return z.BitVecVal(value & MASK,256)
def simple(value):return z.simplify(value)
def number(value):
    value=simple(value)
    if not z.is_bv_value(value):raise Unsupported('nonconstant size/target')
    return value.as_long()
def truth(condition):return z.If(condition,bv(1),bv(0))


class Unsupported(Exception):pass


def integer(value,reason):
    try:return number(value)
    except Unsupported:raise Unsupported(reason)


def _call_may_reach(call, target):
    """Could this call reach `target`, so that its undecoded calldata might be the effect being looked for?

    Asked as a satisfiability question rather than by comparing symbols: the callee is often a value read from
    storage, so a syntactic comparison would say "different" for a target that can in fact be equal. A call that
    provably goes somewhere else cannot have produced this effect; one that might leaves it open.
    """
    reached = Engine._as_160(call['target'])
    wanted = Engine._as_160(target)
    if reached.eq(wanted):
        return True
    if z.is_bv_value(reached) and z.is_bv_value(wanted):
        return reached.as_long() == wanted.as_long()
    probe = z.Solver()
    probe.set(timeout=100)
    probe.add(call['success'] == 1, reached == wanted)
    return probe.check() == z.sat

@dataclass
class State:
    block: str
    env: dict
    memory: object
    storage: object
    conditions: list
    path: list = field(default_factory=list)
    visits: dict = field(default_factory=dict)
    calls: list = field(default_factory=list)
    logs: list = field(default_factory=list)
    reads: list = field(default_factory=list)
    writes: list = field(default_factory=list)
    # Storage array as it was immediately before each entry of `writes`, index-aligned with it.
    write_pre: list = field(default_factory=list)
    branches: list = field(default_factory=list)
    returndata_size: object = field(default_factory=lambda:bv(0))
    returndata: object = None
    frames: list = field(default_factory=list)
    order: dict = field(default_factory=dict)
    apps: list = field(default_factory=list)
    abstracted: int = 0
    opaque: list = field(default_factory=list)

    def branch(self,target,condition=None):
        return State(target,dict(self.env),self.memory,self.storage,
                     self.conditions+([condition] if condition is not None else []),list(self.path),dict(self.visits),
                     list(self.calls),list(self.logs),list(self.reads),list(self.writes),list(self.write_pre),
                     list(self.branches),
                     self.returndata_size,self.returndata,list(self.frames),dict(self.order),list(self.apps),self.abstracted,
                     list(self.opaque))


def _contains(expression, needle) -> bool:
    """Is `needle` a subterm of `expression`? A syntactic walk, used to skip hopeless solver calls."""
    if expression.eq(needle):
        return True
    if not z.is_app(expression):
        return False
    return any(_contains(child, needle) for child in expression.children())


class Engine:
    def __init__(self,facts,policy=None,config=None):
        self.facts=facts;self.policy=policy or {}
        self.config={'max_states':2048,'max_block_visits':2,'wall_seconds':30,'solver_timeout_ms':1000,
                     'max_copy_bytes':512,'max_hash_bytes':256,'max_call_depth':4,
                     'storage_hash_separation':False,**(config or {})}
        self.initial_storage=z.Array('storage_initial',B,B)
        # Memory, calldata and code are modelled at 32-byte word granularity, indexed by byte
        # offset. This keeps ABI-decoding formulas tractable; documented in the scope note.
        self.calldata=z.Array('calldata_word',B,B)
        self.caller=z.BitVec('caller',256);self.callvalue=z.BitVec('callvalue',256)
        self.address=z.BitVec('address',256)
        self.calldatasize=bv(self.policy['calldata_size']) if 'calldata_size' in self.policy else z.BitVec('calldata_size',256)
        self.unknown=[];self.unrolled=[];self.finished=[];self.reverted=[];self.statistics=Counter();self.hash_functions={};self.sequence=0
        self.code=z.Array('code_word',B,B)
        self.started=time.monotonic()
        # The deadline belongs to the *phase*. Exploration and checking get separate budgets, and `query` must
        # honour whichever phase is running: a solver call made during checking that is measured against the
        # exploration clock loses the budget the checker was given, which is how a fully explored path ends up
        # reported `unknown` when it could have been decided.
        self.phase='exploration'
        self.deadline=self.started+self.config['wall_seconds']

    def deadline_exceeded(self):
        """Has the current phase run out of time? Counted, so a truncated phase is visible in the statistics."""
        deadline=getattr(self,'deadline',None)
        if deadline is None:
            return False
        if time.monotonic()<=deadline:
            return False
        self.statistics['deadline_hits_'+getattr(self,'phase','unknown')]+=1
        return True

    def check_expired(self,started,budget,examined):
        """Has the checking phase run out of time, after `examined` completed paths?

        A named seam rather than an inline clock read, so the deadline behaviour can be exercised
        deterministically in tests instead of by sleeping. Production always takes the wall-clock branch.
        """
        return time.monotonic()-started>budget

    def query(self,conditions):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:
            # Refusing a query is a truncated phase, not a finding. The caller turns this into `unknown`; the
            # counter is what makes the truncation auditable rather than implied.
            self.statistics['queries_omitted_at_'+self.phase+'_deadline']+=1
            return z.unknown,None
        self.statistics['solver_queries']+=1
        solver=z.Solver()
        # A solver timeout longer than the remaining budget would overshoot the deadline and let the outer
        # process limit kill the row with no verdict at all, so the two are reconciled here.
        solver.set(timeout=max(1,min(int(self.config['solver_timeout_ms']),int(remaining*1000))))
        solver.add(*conditions)
        answer=solver.check()
        if answer==z.unknown:self.statistics['solver_unknown']+=1
        return answer,solver

    def memory_read(self,memory,offset,size=32):
        if size==32:return simple(z.Select(memory,offset))
        if size<32:return simple(z.Extract(size*8-1,0,z.Select(memory,offset)))
        return simple(z.Concat(*[z.Select(memory,offset+bv(i)) for i in range(0,size,32)]))

    def memory_write(self,memory,offset,value):
        return z.Store(memory,offset,value)

    def calldata_read(self,offset):
        return simple(z.Select(self.calldata,offset))

    def hash_memory(self,state,offset,length,instruction='0x0'):
        try:count=number(length)
        except Unsupported:count=None
        if count is None or count>self.config['max_hash_bytes'] or count%32:
            # Dynamic or oversized preimage: keep a distinct opaque value. Any obligation whose key
            # or payload depends on it is reported imprecise rather than analysed as if it were a hash.
            name='opaque_hash_'+instruction.replace('0x','_')
            value=z.BitVec(name,256)
            if name not in state.opaque:state.opaque.append(name)
            self.statistics['opaque_hashes']+=1
            return value
        if count==0:parts=[bv(0)]
        else:parts=[self.memory_read(state.memory,offset+bv(i)) for i in range(0,count,32)]
        function=self.hash_functions.setdefault(count,z.Function('keccak_%d'%count,*([B]*len(parts)),B))
        value=function(*parts)
        # Ideal-hash assumption only for this bounded set of observed preimages.
        for old_count,old_parts,old_value in state.apps:
            equal=z.And(*[a==b for a,b in zip(parts,old_parts)]) if old_count==count else z.BoolVal(False)
            state.conditions.append(z.Or(equal,value!=old_value))
        state.apps.append((count,parts,value))
        return value

    def external_call(self,state,ins,args,value,out_offset,out_size,input_offset=None,input_size=None):
        key=ins.id.replace('0x','_');success=z.BitVec('call_success'+key,256)
        ret_size=z.BitVec('return_size'+key,256);ret_data=z.Array('return_data'+key,B,B)
        state.conditions += [z.Or(success==0,success==1),z.ULE(ret_size,bv(self.config['max_copy_bytes']))]
        # The calldata an outgoing call carries is what makes a token transfer recognisable. Reading it
        # here is cheap and keeps the selector and the first two arguments available to a binding check.
        selector=None;input_words=None
        if input_offset is not None and input_size is not None:
            try:
                selector=z.Extract(255,224,self.memory_read(state.memory,input_offset))
                input_words=[self.abi_argument(state.memory,input_offset,index) for index in range(3)]
            except (Unsupported,ValueError,z.Z3Exception):
                selector=None;input_words=None
        try:count=number(out_size)
        except Unsupported:count=None
        if count is None:
            self.statistics['memory_abstracted']+=1
            for i in range(0,self.config['max_copy_bytes'],32):
                stored=z.Select(state.memory,out_offset+bv(i))
                state.memory=z.Store(state.memory,out_offset+bv(i),z.If(z.ULT(bv(i),ret_size),z.Select(ret_data,bv(i)),stored))
        elif count:
            if count>self.config['max_copy_bytes']:raise Unsupported('large call output')
            for i in range(0,count,32):
                state.memory=z.Store(state.memory,out_offset+bv(i),z.If(z.ULT(bv(i),ret_size),z.Select(ret_data,bv(i)),z.Select(state.memory,out_offset+bv(i))))
        state.returndata_size=ret_size;state.returndata=ret_data
        state.calls.append({'instruction':ins.id,'opcode':ins.op,'target':args[1],'value':value,'success':success,
                            'input_selector':selector,'input_words':input_words,
                            'input_offset':str(simple(input_offset)) if input_offset is not None else None,
                            'input_size':str(simple(input_size)) if input_size is not None else None,
                            'output_abstracted':count is None,'path_index':len(state.path)})
        return success

    def copy_words(self,state,ins,destination,source,length,reader):
        # Word-granular copy bounded to a window; bytes outside the window keep their old contents.
        window=self.config['max_copy_bytes']
        try:count=number(length)
        except Unsupported:count=None
        if count is not None:
            window=max(min(count,self.config['max_copy_bytes']),32)
        for i in range(0,window,32):
            stored=z.Select(state.memory,destination+bv(i))
            value=reader(source+bv(i)) if count is not None and i<count else z.If(z.ULT(bv(i),length),reader(source+bv(i)),stored)
            state.memory=z.Store(state.memory,destination+bv(i),value)

    def exponent(self,a,b):
        count=integer(b,'symbolic exponent');value=bv(1);base=a
        while count:
            if count&1:value=value*base
            base=base*base;count>>=1
        return value

    def assign(self,state,name,value):
        self.sequence+=1;state.env[name]=value;state.order[name]=self.sequence

    def use(self,state,key):
        if key in state.env:return state.env[key]
        if key in self.facts.constants:return bv(self.facts.constants[key])
        raise Unsupported('undefined SSA value '+key)

    def operation(self,state,ins):
        op=ins.op
        if op=='PHI':
            # PHI operands follow the block's `prev` order, so the incoming edge selects the operand.
            # A loop body may repeat the header's PHI with one predecessor; that copy takes the value
            # already resolved for the identical PHI in the header of the same iteration.
            block=self.facts.blocks.get(state.path[-1]) if state.path else None
            previous=state.path[-2] if len(state.path)>1 else None
            predecessors=block.predecessors if block else []
            if len(ins.defines)!=1:raise Unsupported('PHI result arity')
            value=None
            if previous is not None and previous in predecessors and len(ins.uses)==len(predecessors):
                name=ins.uses[predecessors.index(previous)]
                value=state.env.get(name)
            if value is None:
                defined=[key for key in ins.uses if key in state.env]
                if len(defined)==1:value=state.env[defined[0]]
                elif defined:
                    twins=[state.env[name] for name in self.facts.phi_twins.get(tuple(ins.uses),[])
                           if name in state.env and name!=ins.defines[0]]
                    if len(twins)==1:value=twins[0]
                    elif len(twins)>1:value=state.env[defined[-1]]
                    else:
                        # Loop-carried value: the most recently assigned operand is this iteration's.
                        value=max(defined,key=lambda name:state.order.get(name,0))
                        value=state.env[value]
            if value is None:raise Unsupported('ambiguous PHI')
            self.assign(state,ins.defines[0],value)
            return None,[]
        args=[self.use(state,key) for key in ins.uses];value=None
        a=args[0] if args else None;b=args[1] if len(args)>1 else None
        if op=='CONST':
            if len(ins.defines)!=1 or ins.defines[0] not in self.facts.constants:raise Unsupported('constant absent')
            value=bv(self.facts.constants[ins.defines[0]])
        elif op=='ADD':value=a+b
        elif op=='SUB':value=a-b
        elif op=='MUL':value=a*b
        elif op=='DIV':value=z.If(b==0,bv(0),z.UDiv(a,b))
        elif op=='MOD':value=z.If(b==0,bv(0),z.URem(a,b))
        elif op=='SDIV':value=z.If(b==0,bv(0),a/b)
        elif op=='SMOD':value=z.If(b==0,bv(0),z.SRem(a,b))
        elif op=='AND':value=a&b
        elif op=='OR':value=a|b
        elif op=='XOR':value=a^b
        elif op=='NOT':value=~a
        elif op=='SHL':value=b<<a
        elif op=='SHR':value=z.LShR(b,a)
        elif op=='SAR':value=b>>a
        elif op=='EQ':value=truth(a==b)
        elif op=='LT':value=truth(z.ULT(a,b))
        elif op=='GT':value=truth(z.UGT(a,b))
        elif op=='SLT':value=truth(a<b)
        elif op=='SGT':value=truth(a>b)
        elif op=='ISZERO':value=truth(a==0)
        elif op=='CALLER':value=self.caller
        elif op=='ADDRESS':value=self.address
        elif op=='CALLVALUE':value=self.callvalue
        elif op=='CALLDATASIZE':value=self.calldatasize
        elif op=='CALLDATALOAD':value=self.calldata_read(a)
        elif op=='CALLDATACOPY':
            self.copy_words(state,ins,a,b,args[2],lambda index:self.calldata_read(index))
        elif op=='CODECOPY':
            self.copy_words(state,ins,a,b,args[2],lambda index:simple(z.Select(self.code,index)))
        elif op=='EXP':value=self.exponent(a,b)
        elif op=='BYTE':
            offset=integer(a,'symbolic byte offset')
            value=z.BitVecVal(0,256) if offset>31 else z.ZeroExt(248,z.Extract(255-offset*8,248-offset*8,b))
        elif op=='MSTORE':state.memory=self.memory_write(state.memory,a,b)
        elif op=='MSTORE8':
            offset=integer(a,'symbolic byte offset')
            word=bv(offset//32*32);shift=(offset%32)*8
            old=z.Select(state.memory,word)
            state.memory=z.Store(state.memory,word,(old&bv(~(0xff<<shift)&MASK))|(z.ZeroExt(248,z.Extract(7,0,b))<<shift))
        elif op=='MLOAD':value=self.memory_read(state.memory,a)
        elif op=='SHA3':value=self.hash_memory(state,a,b,ins.id)
        elif op=='SLOAD':
            value=z.Select(state.storage,a);state.reads.append((ins.id,a,value))
        elif op=='SSTORE':
            # The array before the store is kept alongside the write: an allowance rule has to show that
            # an entry became its previous value plus or minus the declared amount, which is a statement
            # about the previous value and cannot be recovered from the final storage array.
            state.write_pre.append(state.storage)
            state.storage=z.Store(state.storage,a,b);state.writes.append((ins.id,a,b))
        elif op=='CALL':
            if len(args)!=7:raise Unsupported('CALL arity')
            value=self.external_call(state,ins,args,args[2],args[5],args[6],args[3],args[4])
        elif op in ['STATICCALL','DELEGATECALL']:
            if len(args)!=6:raise Unsupported(op+' arity')
            value=self.external_call(state,ins,args,bv(0),args[4],args[5],args[2],args[3])
        elif op=='RETURNDATASIZE':value=state.returndata_size
        elif op=='RETURNDATACOPY':
            if state.returndata is None:raise Unsupported('returndata absent')
            dest,source,length=args
            state.conditions += [z.ULE(length,bv(self.config['max_copy_bytes']))]
            for i in range(0,self.config['max_copy_bytes'],32):
                stored=z.Select(state.memory,dest+bv(i))
                state.memory=z.Store(state.memory,dest+bv(i),z.If(z.ULT(bv(i),length),z.Select(state.returndata,source+bv(i)),stored))
        elif op.startswith('LOG'):
            state.logs.append({'instruction':ins.id,'topics':args[2:],'length':args[1],
                               'first_word':self.memory_read(state.memory,args[0]),
                               # Declared-movement binding needs a specific data word, and the first
                               # word of a log is often not the amount. Keep the leading words.
                               'words':[self.memory_read(state.memory,args[0]+bv(32*index)) for index in range(4)],
                               # An allowance announcement is realised by the stored change itself, not by a
                               # token transfer, so the check needs to know what had been written by then.
                               'writes_before':len(state.writes),
                               'path_index':len(state.path)})
        elif op in ['GAS','ADDRESS','ORIGIN','NUMBER','TIMESTAMP','CHAINID','SELFBALANCE','BALANCE','EXTCODESIZE','EXTCODEHASH']:
            suffix=hashlib.sha256(str(args).encode()).hexdigest()[:12] if args else ''
            value=z.BitVec('environment_'+op+suffix,256)
        elif op=='CALLPRIVATE':
            if not args:raise Unsupported('private call arity')
            caller=state.path[-1]
            entry=self.facts.resolve_in_context(caller,integer(args[0],'symbolic private-call target'))
            formals=self.facts.formal_bindings(entry);actuals=args[1:]
            if len(actuals)!=len(formals):raise Unsupported('private call argument mismatch')
            for name,value in zip(formals,actuals):self.assign(state,name,simple(value))
            # Void Solidity helpers can still carry a formal return address. Result arity says nothing
            # about whether execution must resume in the caller. Stopping at _approve's RETURNPRIVATE
            # dropped the subsequent _burn in the released Synapse burnFrom path.
            position=self.facts.return_position(entry)
            if position is not None:
                if len(state.frames)>=self.config['max_call_depth']:raise Unsupported('call depth bound')
                if position>=len(actuals):raise Unsupported('unknown return-address position')
                resume=self.facts.resolve_return(caller,entry,integer(actuals[position],'symbolic return address'),state.path)
                state.frames.append({'return':resume,'defines':list(ins.defines),'entry':entry})
                self.statistics['private_call_frames']+=1
            elif ins.defines:
                raise Unsupported('unknown return-address position')
            return 'CALLPRIVATE_ENTER',[entry]
        elif op=='RETURNPRIVATE':
            if not state.frames:
                # A public entry point returns to the external caller; no frame exists. This build emits
                # RETURNPRIVATE for that case, so it is a normal success and not a desynchronisation.
                return 'STOP',args
            frame=state.frames.pop();values=args[1:]
            if len(values)!=len(frame['defines']):
                # A mismatch means the frame chain or the return arity is not understood. Binding the
                # surplus to free values would turn an unproven path into a feasible one, so the path
                # stays an explicit unknown.
                raise Unsupported('private return arity: callee %s returns %d value(s), caller defines %d %s'
                                  %(frame['entry'],len(values),len(frame['defines']),frame['defines']))
            for name,value in zip(frame['defines'],values):self.assign(state,name,simple(value))
            return 'RETURNPRIVATE',[frame['return']]
        elif op in ['JUMP','JUMPI','STOP','RETURN','REVERT','INVALID','THROW']:
            return op,args
        else:raise Unsupported('unsupported opcode '+op)
        if value is not None:
            if len(ins.defines)!=1:raise Unsupported('result arity '+op)
            self.assign(state,ins.defines[0],simple(value))
        return None,args

    def run(self):
        constraints=[z.ULT(self.caller,bv(1<<160)),self.caller!=bv(0),z.ULE(self.calldatasize,bv(4096))]
        if 'selector' in self.policy:
            constraints += [z.UGE(self.calldatasize,bv(4)),z.LShR(self.calldata_read(bv(0)),224)==bv(int(self.policy['selector'],16))]
        # A rule about `deposit(asset, amount)` is a rule about *a* call, not about every call the ABI
        # admits. Left free, the calldata lets the solver pick a degenerate request (asset = 0) and
        # manufacture a mismatch no protocol could ever make, which is an alert about the policy rather
        # than about the contract. Pinning the analysed arguments to the request under test keeps the
        # query about the same transaction the concrete run executed.
        for offset,value in sorted((self.policy.get('argument_values') or {}).items()):
            constraints.append(self.calldata_read(bv(int(offset)))==bv(int(value)))
        # The sending account is part of the analysed request for the same reason: `msg.sender` selects the
        # depositor in a custodial deposit, and a verdict about a different sender is a verdict about a
        # different transaction.
        if 'caller' in self.policy:
            constraints.append(self.caller==bv(int(self.policy['caller'])))
        if 'callvalue' in self.policy:
            # The value sent with the analysed call is part of the request: a native payment forwards
            # `msg.value`, so leaving it free analyses a different transaction from the executed one.
            constraints.append(self.callvalue==bv(int(self.policy['callvalue'])))
        pending=[State(self.facts.entry,{},z.K(B,bv(0)),self.initial_storage,constraints)]
        self.phase='exploration'
        self.deadline=self.started+self.config['wall_seconds']
        while pending:
            if self.statistics['states']>=self.config['max_states'] or time.monotonic()>self.deadline:
                self.unknown.append({'reason':'global analysis bound','pending_states':len(pending)});break
            state=pending.pop();self.statistics['states']+=1
            count=state.visits.get(state.block,0)+1;state.visits[state.block]=count
            if count>self.config['max_block_visits']:
                # Deeper iterations of an already-analysed loop body: recorded, not an analysis gap.
                self.unrolled.append({'block':state.block,'visits':count});continue
            answer,_=self.query(state.conditions)
            if answer==z.unsat:self.statistics['infeasible_states']+=1;continue
            if answer!=z.sat:self.unknown.append({'reason':'solver unknown','block':state.block});continue
            block=self.facts.blocks.get(state.block)
            if block is None:self.unknown.append({'reason':'missing block','block':state.block});continue
            state.path.append(block.id)
            try:
                terminal=None;arguments=[]
                for ins in block.instructions:
                    control,args=self.operation(state,ins)
                    if control:terminal=control;arguments=args;break
                if terminal in ['STOP','RETURN']:
                    self.finished.append(state);self.statistics['successful_paths']+=1
                elif terminal in ['REVERT','INVALID','THROW']:
                    self.statistics['reverting_paths']+=1
                    # Retained so an authorization gate can be recognised by "this path reverts
                    # precisely because the caller is not the owner".
                    self.reverted.append(state)
                elif terminal=='JUMPI':
                    if len(block.successors)!=2:raise Unsupported('JUMPI successor count')
                    target=self.facts.resolve_target(block,integer(arguments[0],'symbolic jump target'))
                    other=next(s for s in block.successors if s!=target)
                    condition=arguments[1]!=0
                    state.branches.append((ins.id,arguments[1]))
                    pending.extend([state.branch(target,condition),state.branch(other,z.Not(condition))])
                elif terminal=='JUMP':
                    target=self.facts.resolve_target(block,integer(arguments[0],'symbolic jump target'))
                    pending.append(state.branch(target))
                elif terminal in ['CALLPRIVATE_ENTER','RETURNPRIVATE']:
                    pending.append(state.branch(arguments[0]))
                elif len(block.successors)==1:pending.append(state.branch(block.successors[0]))
                else:raise Unsupported('unterminated/ambiguous block')
            except (Unsupported,ValueError,z.Z3Exception) as error:
                self.unknown.append({'reason':str(error),'block':block.id,'path':state.path,'instruction':ins.id if block.instructions else None})
        return self

    def policy_key(self,state,policy):
        # A mapping key is keccak256(abi.encode(key)). The key may be one calldata word or one
        # element of a calldata array; the element index stays symbolic so the obligation is
        # checked for an arbitrary message, independent of loop unrolling.
        kind=policy['kind']
        if kind=='mapping_boolean':
            key=self.calldata_read(bv(policy['key_calldata_offset']));conditions=[]
        elif kind=='array_indexed_mapping':
            # ABI array offsets are relative to the argument block, which starts after the selector.
            # The element address is folded into one constant so it canonicalises with the contract's
            # own `add(constant, dynamic_pointer)` term.
            base=int(policy.get('arg_base_offset',4))
            pointer=self.calldata_read(bv(policy['array_head_offset']))
            index=policy.get('element_index')
            if index=='symbolic':
                index=z.BitVec('replay_element_index',256)
                conditions=[z.ULT(index,self.calldata_read(bv(base)+pointer))]
                key=self.calldata_read(bv(base+32)+pointer+index*bv(32))
            else:
                conditions=[]
                key=self.calldata_read(bv(base+32+32*int(index if index is not None else 0))+pointer)
        else:raise Unsupported('unsupported replay policy kind '+str(kind))
        function=self.hash_functions.setdefault(64,z.Function('keccak_64',B,B,B))
        return function(key,bv(policy['slot'])),conditions

    @staticmethod
    def contaminated(state,expression):
        if not state.opaque:return False
        names={variable.decl().name() for variable in z.z3util.get_vars(expression)}
        return any(name in names for name in state.opaque)

    def effects(self,state):
        kinds=set(self.policy.get('effects',['value_call']))
        rows=[]
        for call in state.calls:
            if 'plain_call' in kinds and call['opcode']=='CALL':rows.append(call['success']==1)
            if 'value_call' in kinds:rows.append(z.And(call['success']==1,z.UGT(call['value'],bv(0))))
        for log in state.logs:
            if 'log' in kinds:rows.append(z.BoolVal(True))
        if 'storage_write' in kinds and state.writes:
            # A committed state change is an effect even without an external call, e.g. a token mint.
            rows.append(z.BoolVal(True))
        return z.Or(*rows) if rows else z.BoolVal(False)

    def trace(self,state,obligation=None):
        """Project a witness into the (entry, vulnerable function, state variables) unit.

        SmartAxe scores a CCV as a trace: taint from a public entry reaching a vulnerable function,
        together with the state variables that function subverts. This rebuilds that shape from the
        explored path so the two outputs are comparable in form.
        """
        functions=[]
        for block in state.path:
            name=self.facts.function_of_block(block)
            if name and (not functions or functions[-1]!=name):functions.append(name)
        entry=next((name for name in functions if name!='__function_selector__'),None)
        writes=[]
        for instruction,key,value in state.writes:
            block=self.facts.block_of_instruction(instruction)
            writes.append({'instruction':self.facts.canonical_identifier(instruction),'instruction_raw':instruction,
                           'function':self.facts.display_name(self.facts.function_of_block(block)),
                           'key':str(simple(key)),'value':str(simple(value))})
        candidates=[call for call in state.calls]
        if obligation=='replay_after_failed_effect':candidates=[call for call in candidates if simple(call['target'])==simple(self.address)]
        effect=candidates[-1] if candidates else None
        vulnerable=None
        write_effect=None
        if effect is None and state.writes:
            # The obligation was satisfied by a committed state change; report that write as the effect
            # so the trace is coherent with the reason the verdict was reached.
            instruction,key,value=state.writes[-1]
            write_effect={'instruction':self.facts.canonical_identifier(instruction),'instruction_raw':instruction,
                          'opcode':'SSTORE','key':str(simple(key)),'value':str(simple(value))}
            block=self.facts.block_of_instruction(instruction)
            vulnerable=self.facts.display_name(self.facts.function_of_block(block))
        if effect:
            block=self.facts.block_of_instruction(effect['instruction'])
            vulnerable=self.facts.display_name(self.facts.function_of_block(block))
        if vulnerable is None and functions:vulnerable=self.facts.display_name(functions[-1])
        return {'entry':{'function':entry,'name':self.facts.display_name(entry)},
                'vulnerable_function':vulnerable,
                'state_variables':[row for row in writes if row['function']==vulnerable] or writes,
                'effect':None if effect is None else {'instruction':self.facts.canonical_identifier(effect['instruction']),
                                                      'instruction_raw':effect['instruction'],
                                                      'opcode':effect['opcode'],
                                                      'target':str(simple(effect['target'])),'value':str(simple(effect['value']))},
                'write_effect':write_effect,
                'call_chain':[self.facts.display_name(name) for name in functions]}

    def evidence(self,state,solver,obligation=None):
        model=solver.model();count=number(self.calldatasize) if z.is_bv_value(self.calldatasize) else 128
        words=min(max(count//32+1,1),16)
        calldata=[hex(model.eval(z.Select(self.calldata,bv(i*32)),model_completion=True).as_long()&MASK) for i in range(words)]
        declarations=[]
        for log in state.logs:
            declarations.append({'instruction':self.facts.canonical_identifier(log['instruction']),
                                 'instruction_raw':log['instruction'],
                                 'path_index':log.get('path_index'),
                                 'topics':[hex(int(model.eval(topic,model_completion=True).as_long())&MASK) for topic in log['topics']],
                                 'words':[hex(int(model.eval(word,model_completion=True).as_long())&MASK) for word in (log.get('words') or [])],
                                 'writes_before':log.get('writes_before')})
        return {'path':state.path,'path_canonical':[self.facts.canonical_identifier(block) for block in state.path],
                'caller':hex(model.eval(self.caller,model_completion=True).as_long()&((1<<160)-1)),
                'calldata_words_at_32_byte_offsets':calldata,
                'log_declarations':declarations,
                'trace':self.trace(state,obligation),
                'calls':[{'instruction':self.facts.canonical_identifier(c['instruction']),
                          'instruction_raw':c['instruction'],
                          'target':str(simple(c['target'])),
                          'value':str(simple(c['value'])),
                          'path_index':c.get('path_index'),
                          'input_selector':(hex(model.eval(c['input_selector'],model_completion=True).as_long())
                                            if c.get('input_selector') is not None else None),
                          'input_words':([hex(model.eval(word,model_completion=True).as_long())
                                          for word in c['input_words']] if c.get('input_words') is not None else None),
                          'success_in_model':model.eval(c['success'],model_completion=True).as_long()} for c in state.calls],
                'storage_reads':[{'instruction':self.facts.canonical_identifier(i),'instruction_raw':i,
                                  'key':str(simple(k)),
                                  'initial_model_value':str(model.eval(z.Select(self.initial_storage,k),model_completion=True))} for i,k,v in state.reads],
                'storage_writes':[{'instruction':self.facts.canonical_identifier(i),'instruction_raw':i,
                                   'key':str(simple(k)),'value':str(simple(v))} for i,k,v in state.writes],
                'validation':'abstract witness; initial-state reachability, hash interpretation and concrete replay require separate validation'}

    def counter_increments(self, state, initial_storage):
        """Diagnostic recognition of an increment, never proof of replay protection.

        An increment may update an unrelated statistic or generate an outgoing deposit
        identifier. It neither binds a consumed key to the authenticated incoming
        message nor rejects a second execution. Fixed-width increments may also wrap.
        Replay verdicts therefore use only the declared policy key and guard.
        """
        return self._scan_for_counter(state, initial_storage)

    @staticmethod
    def _scan_for_counter(state, initial_storage):
        tried = set()
        for _instruction, key, value in state.writes:
            name = str(simple(key))
            if name in tried:
                continue
            tried.add(name)
            previous = z.Select(initial_storage, key)
            if not z.is_bv(previous):
                continue
            bits = previous.sort().size()
            probe = z.Const('__counter_probe', previous.sort())
            rewritten = z.substitute(value, (previous, probe))
            if rewritten.eq(value):
                continue
            for width in (8, 16, 32, 64, 128, 256):
                if width > bits:
                    break
                if width < bits:
                    expected = z.Concat(z.Extract(bits - 1, width, probe), z.Extract(width - 1, 0, probe) + 1)
                else:
                    expected = probe + 1
                if z.eq(z.simplify(rewritten), z.simplify(expected)):
                    return True
        return False

    # Transfer selectors that move an asset for a bound recipient and amount.
    TRANSFER_SELECTORS = (0xa9059cbb, 0x23b872dd)

    # Each token interface has its own argument layout. `recipient` is the argument index of the payee,
    # `amount` the index of the amount; `recipient: None` means the asset contract itself receives nothing
    # and only the amount can be bound. Getting this wrong rejects a correctly formed transfer.
    TOKEN_INTERFACES = {
        0xa9059cbb: {"name": "transfer(address,uint256)", "recipient": 0, "amount": 1},
        0x23b872dd: {"name": "transferFrom(address,address,uint256)", "recipient": 1, "amount": 2},
        0x2ccb1b30: {"name": "transferTo(address,uint256)", "recipient": 0, "amount": 1},
        0x4000aea0: {"name": "transferAndCall(address,uint256,bytes)", "recipient": 0, "amount": 1},
        0x42966c68: {"name": "burn(uint256)", "recipient": None, "amount": 0},
        0x79cc6790: {"name": "burnFrom(address,uint256)", "recipient": None, "amount": 1},
    }

    @staticmethod
    def _keccak_applications(expression, name='keccak_64'):
        """Every `keccak_64` application inside a storage key, innermost included."""
        found = []
        stack = [expression]
        while stack:
            node = stack.pop()
            if not z.is_app(node):
                continue
            if node.decl().name() == name and node.num_args() == 2:
                found.append(node)
            stack.extend(node.children())
        return found

    @staticmethod
    def _as_160(expression):
        """The 160-bit value the compiler's address cleaning leaves behind.

        `abi.encode` of an address stores `Concat(0, Extract(159, 0, x))`, while an indexed event parameter
        is the bare 160-bit value, so the two are compared after stripping exactly that cleaning.
        """
        if not z.is_bv(expression):
            return expression
        if expression.sort().size() == 160:
            return expression
        if z.is_app(expression) and expression.decl().name() == 'Concat' and expression.num_args() == 2:
            high, low = expression.children()
            if z.is_bv_value(high) and high.as_long() == 0:
                return Engine._as_160(low)
        return z.Extract(159, 0, expression)

    @staticmethod
    def _nested_entries(key):
        """Every `(outer preimage, inner preimage, inner constant)` a nested mapping key exposes.

        `keccak(outer, keccak(inner, slot))` is what the compiler emits for
        `mapping(address => mapping(address => uint))`. Returning the pair lets a rule bind *both* parties a
        custody entry is keyed by -- the account credited and the asset credited -- instead of guessing one.
        """
        applications = Engine._keccak_applications(key)
        entries = []
        for outer in applications:
            for inner in applications:
                if inner is outer or not z.eq(outer.arg(1), inner):
                    continue
                slot = inner.arg(1)
                if not z.is_bv_value(slot):
                    continue
                entries.append((Engine._as_160(outer.arg(0)), Engine._as_160(inner.arg(0)),
                                slot.as_long()))
        return entries

    def _custodial_deposit_realisation(self, state, log, binding, words):
        """Terms under which a declared deposit is realised, and whether it is decidable.

        A deposit announcement does not say "this many tokens were sent to the vault". It says "this much was
        taken into custody and credited to the vault", and the two asset kinds realise that differently:

          native  a successful value call of the declared amount reaching the declared vault, and only when the
                  declaration names the native asset
          token   the tokens are pulled *to this contract* -- they stay here -- and the declared vault's ledger
                  entry for the declared asset grows by the declared amount

        Three specific mistakes are guarded against, each of which was found by probing this helper directly:

          * the compiler emits `keccak(asset, keccak(vault, slot))` for `ledger[vault][asset]`, so the outer
            preimage is the **asset** and the inner one is the **vault**. Reading them the other way round
            accepts a write to the wrong entry.
          * a ledger write is only a credit if the stored value *grows* by the declared amount. Writing zero
            "equals" previous + amount for the single previous value -amount, so a value test alone is vacuous.
          * a native payment cannot realise a declaration that names a token: the declared asset has to be the
            zero sentinel for the native branch to apply at all.

        Returns `(terms, undecidable)`.
        """
        vault_topic = binding.get('recipient_topic_index', 1)
        asset_topic = binding.get('asset_topic_index')
        amount_index = binding.get('amount_word_index', 0)
        if asset_topic is None or len(log['topics']) <= max(vault_topic, asset_topic):
            return [], True
        vault = Engine._as_160(log['topics'][vault_topic])
        asset = Engine._as_160(log['topics'][asset_topic])
        if amount_index >= len(words):
            return [], True
        amount = words[amount_index]
        zero = bv(0)
        caller = Engine._as_160(self.caller)
        # `_party_equality` compares at 160 bits, so the zero sentinel has to be the same width.
        native_declaration = Engine._party_equality(asset, z.BitVecVal(0, 160))

        terms = []
        for call in state.calls:
            # native custody: only for a declaration that names the native asset, and only if the declared
            # amount actually reaches the declared vault.
            terms.append(z.And(native_declaration, call['success'] == 1,
                               Engine._as_160(call['target']) == vault,
                               call['value'] == amount, call['value'] != zero))
            selector = call.get('input_selector')
            arguments = call.get('input_words') or []
            if selector is None or len(arguments) < 3:
                # An undecoded call may still be the pull that realises this deposit. The compiler emits the
                # pull through the token address it read from storage, so the callee is a symbolic value the
                # engine cannot decode here; saying "no pull happened" would report a deposit as unrealised on
                # the strength of a call whose arguments were never read. That is an explicit unknown.
                if _call_may_reach(call, asset):
                    return [], True
                continue
            pull = Engine.TOKEN_INTERFACES[0x23b872dd]
            pulled = z.And(call['success'] == 1, Engine._as_160(call['target']) == asset,
                           call['target'] != zero,
                           selector == z.BitVecVal(0x23b872dd, selector.size()),
                           Engine._as_160(arguments[0]) == caller,
                           Engine._as_160(arguments[pull['recipient']]) == Engine._as_160(self.address),
                           arguments[pull['amount']] == amount)
            credited = []
            for index, write in enumerate(state.writes):
                if index % 32 == 0 and self.deadline_exceeded():
                    return [], True
                if len(write) != 3:
                    continue
                _instruction, key, value = write
                previous = state.write_pre[index] if index < len(state.write_pre) else state.storage
                for outer, inner, slot in Engine._nested_entries(key):
                    if binding.get('ledger_slot') is not None and slot != int(binding['ledger_slot']):
                        continue
                    credited.append(z.And(Engine._party_equality(outer, asset),
                                          Engine._party_equality(inner, vault),
                                          Engine._moved_by(value, previous, key, amount, 1)))
            if credited:
                terms.append(z.And(pulled, z.Or(*credited)))
        return terms, False

    @staticmethod
    def _party_equality(expression, target):
        """The constraint that a key preimage denotes the declared party.

        This is returned as a term, never evaluated as an assumption. Asking the solver whether the two
        addresses *could* coincide is satisfiable for almost any pair of symbolic addresses, so treating
        that answer as "they are the same party" silently equates distinct parties. As a constraint, the
        equality holds only in the models where it really does, and the surrounding obligation keeps its
        uncertainty.
        """
        left = Engine._as_160(expression)
        if left.eq(target):
            return z.BoolVal(True)
        if z.is_bv_value(left) and z.is_bv_value(target):
            return z.BoolVal(False)
        return left == target

    @staticmethod
    def _allowance_entries(key, slot):
        """The `(party, spender)` pairs a storage key exposes for a declared base slot.

        A flat `mapping(address => uint256)` yields `keccak(party, slot)`: party and spender coincide. A
        nested `mapping(address => mapping(address => uint256))` yields `keccak(spender, keccak(party,
        slot))`, so the party is the preimage one level in and the spender wraps it.
        """
        applications = Engine._keccak_applications(key)
        entries = []
        for application in applications:
            second = application.arg(1)
            if not (z.is_bv_value(second) and second.as_long() == int(slot)):
                continue
            party = Engine._as_160(application.arg(0))
            spender = None
            for parent in applications:
                if z.eq(parent.arg(1), application):
                    spender = Engine._as_160(parent.arg(0))
                    break
            entries.append((party, spender))
        return entries

    @staticmethod
    def _moved_by(value, previous_array, key, amount, sign):
        """Is the stored value the previous value plus (sign=1) or minus (sign=-1) the declared amount?

        The test is an identity in the previous value, established by replacing it with a fresh constant
        and asking whether the residual can differ. Comparing the stored value with a constant instead is
        vacuous under arbitrary initial storage: a write of zero would "equal" previous+100 for the single
        previous value -100, and so a contract could announce moving 100 while writing nothing.
        """
        # Fast path: if the stored value does not even read this entry, it cannot be an increment of it. This
        # is a syntactic check, so it costs nothing and avoids a solver call per storage write on contracts
        # with many writes.
        read = z.Select(previous_array, key)
        if not _contains(value, read):
            return False
        constant = z.BitVec('__allowance_previous', 256)
        rewritten = z.substitute(value, (read, constant))
        expected = constant + amount if sign > 0 else constant - amount
        if z.eq(z.simplify(rewritten), z.simplify(expected)):
            return True
        probe = z.Solver()
        probe.set(timeout=200)
        probe.add(z.simplify(rewritten) != z.simplify(expected))
        return probe.check() == z.unsat

    def _allowance_realisation(self, state, log, binding, words):
        """Terms under which an allowance announcement is realised, and whether it is decidable.

        The announcement says value moved *between two entries*: the entry of the spender giving the
        allowance up shrinks by the declared amount, and the entry of the spender receiving it grows by the
        same amount. Both halves are required, so an unrelated write cannot clear the obligation and neither
        can a movement in one direction only.

        Returns `(terms, undecidable)`. An empty term list with `undecidable=False` means the layout was
        recognised and nothing realised it, which is the declared violation.
        """
        slot = binding.get('allowance_slot')
        if slot is None:
            return [], True
        subject_topic = binding.get('allowance_subject_topic_index',
                                    binding.get('allowance_party_topic_index'))
        spender_topic = binding.get('allowance_spender_topic_index')
        amount_index = binding.get('allowance_amount_word_index')
        amount = words[amount_index] if amount_index is not None and amount_index < len(words) else None
        if amount is None:
            return [], True
        if subject_topic is not None and len(log['topics']) > subject_topic:
            subject = Engine._as_160(log['topics'][subject_topic])
        elif binding.get('allowance_party') == 'caller':
            subject = Engine._as_160(self.caller)
        else:
            return [], True
        if spender_topic is not None and len(log['topics']) > spender_topic:
            spender = Engine._as_160(log['topics'][spender_topic])
        else:
            return [], True
        giving = Engine._as_160(self.caller) if binding.get('allowance_previous_spender', 'caller') == 'caller' \
            else None

        entries = []
        for index, write in enumerate(state.writes):
            if index % 32 == 0 and self.deadline_exceeded():
                return [], True
            if len(write) != 3:
                continue
            _instruction, key, value = write
            for party, entry_spender in Engine._allowance_entries(key, int(slot)):
                entries.append((index, key, party, entry_spender, value))
        if not entries:
            # No key exposes the declared slot, so the mapping is keyed differently and the model cannot
            # say whether the announcement was realised.
            return [], True

        gains, losses = [], []
        for index, key, party, entry_spender, value in entries:
            previous = state.write_pre[index] if index < len(state.write_pre) else state.storage
            spender_of_entry = party if entry_spender is None else entry_spender
            holds_subject = Engine._party_equality(party, subject)
            if Engine._moved_by(value, previous, key, amount, 1):
                gains.append(z.And(holds_subject, spender_of_entry == spender))
            if giving is not None and Engine._moved_by(value, previous, key, amount, -1):
                losses.append(z.And(holds_subject, spender_of_entry == giving))
        if not gains or not losses:
            # The declared slot is written, but not in both directions with the declared amount. That is
            # not evidence the movement happened, and not evidence it did not, since an initial value the
            # model does not know could make a one-sided write consistent.
            return [], True
        return [z.And(z.Or(*gains), z.Or(*losses))], False

    @staticmethod
    def abi_argument(memory, offset, index):
        """Read argument `index` of an ABI-encoded call from memory.

        The compiler stores the selector left-aligned in the first word and then encodes the arguments
        starting at `offset + 4`, each as a full 32-byte word. Solidity 0.8.4 emits

            mstore(ptr, shl(224, selector))
            ptr + 0x04 -> abi_encode(to, amount)

        so argument `index` lives at the unaligned key `offset + 4 + 32*index`. Composing it from the
        aligned words 0..n instead reads the selector word and misses the argument entirely, which is why a
        correctly formed transfer used to be rejected.
        """
        return simple(z.Select(memory, offset + bv(4 + 32 * index)))

    def declared_movement_mismatch(self, state, binding):
        """A declaration of movement must be realised by the effect its own payload names.

        Two kinds of declaration are distinguished, because the protocol meaning differs:

        `asset_movement`          the log says assets moved to a recipient. It is realised only by a
                                  successful effect that moves *that asset* to *that recipient* for *that
                                  amount*: a native value call with the declared value, or a token transfer
                                  whose selector is `transfer`/`transferFrom` and whose arguments are the
                                  declared recipient and amount, sent to the declared asset contract.
                                  A call to some unrelated address is never evidence of movement.
        `allowance_reassignment`  the log announces a change of vault allowance. Its protocol meaning is
                                  bookkeeping, so it is realised by the stored allowance change itself and
                                  does **not** require a physical token transfer.

        `binding` fields: topic, recipient_topic_index, asset_topic_index or asset_word_index,
        amount_word_index, require_length_at_least, kind, satisfiers.
        An explicit empty `satisfiers` list disables every satisfier; it is not replaced by defaults.

        Returns a condition satisfiable exactly when a feasible path declares a movement that nothing
        realises. Anything the model cannot bind (missing selector, missing word, unbound symbol) makes the
        satisfier unavailable rather than satisfied.
        """
        kind = binding.get('kind', 'asset_movement')
        signature = int(binding['topic'], 16)
        recipient_index = int(binding.get('recipient_topic_index', 1))
        asset_topic = binding.get('asset_topic_index')
        asset_word = binding.get('asset_word_index')
        amount_word = binding.get('amount_word_index', binding.get('declared_amount_word'))
        source_topic = binding.get('source_topic_index')
        source_word = binding.get('source_word_index')
        if 'satisfiers' in binding:
            satisfiers = binding['satisfiers']
        else:
            satisfiers = ['native_value_call', 'token_transfer'] if kind == 'asset_movement' \
                else ['allowance_write']
        minimum_length = binding.get('require_length_at_least')
        zero = bv(0)
        rows = []
        for log in state.logs:
            if self.deadline_exceeded():
                # The obligation's own processing can outlast the budget: every candidate log walks every storage
                # write and asks the solver about it. An overrun leaves the movement undecided, not clean.
                return z.BoolVal(False), True
            if len(log['topics']) <= recipient_index:
                continue
            if asset_topic is not None and len(log['topics']) <= asset_topic:
                continue
            words = log.get('words') or []
            if asset_word is not None and asset_word >= len(words):
                continue
            if amount_word is not None and amount_word >= len(words):
                continue
            declared = log['topics'][0] == bv(signature)
            if minimum_length is not None:
                declared = z.And(declared, z.UGE(log['length'], bv(int(minimum_length))))
            recipient = log['topics'][recipient_index]
            if asset_topic is not None:
                asset = log['topics'][asset_topic]
            elif asset_word is not None:
                asset = words[asset_word]
            else:
                asset = None
            amount = words[amount_word] if amount_word is not None else None
            if amount is not None:
                # A declaration of a zero movement is realised by doing nothing, so it cannot evidence a
                # mismatch. Without this the cheapest model for every published router is "declare zero, move
                # zero", and the obligation reports violations whose witnesses no concrete run can reproduce.
                declared = z.And(declared, amount != zero)
            if source_topic is not None and len(log['topics']) > source_topic:
                source = log['topics'][source_topic]
            elif source_word is not None and source_word < len(words):
                source = words[source_word]
            else:
                source = None
            realised = []
            unavailable = False
            for call in state.calls:
                if 'native_value_call' in satisfiers and amount is not None:
                    # The declaration must name the native asset. Without this, an ETH payment satisfied a
                    # declaration about a token that was never touched.
                    realised.append(z.And(asset == zero if asset is not None else z.BoolVal(False),
                                          call['success'] == 1, call['target'] == recipient,
                                          call['value'] == amount))
                if 'token_transfer' in satisfiers and asset is not None and amount is not None:
                    selector = call.get('input_selector')
                    arguments = call.get('input_words') or []
                    if selector is None or len(arguments) < 3:
                        unavailable = True
                        continue
                    known_interface = False
                    for code, layout in Engine.TOKEN_INTERFACES.items():
                        # Whether this call could be this interface is asked for every modelled interface,
                        # including the burns: a burn is a *known* effect, so a path whose only call is a
                        # burn is decided, not undecidable.
                        probe = z.Solver(); probe.set(timeout=100)
                        probe.add(*getattr(state, 'conditions', []))
                        probe.add(selector == z.BitVecVal(code, selector.size()))
                        known_interface = known_interface or probe.check() == z.sat
                        # A burn destroys the asset; it pays no recipient. Letting it satisfy a payment let
                        # a burn-only call clear a declaration naming some other recipient, which is why
                        # burn interfaces contribute no realisation term here and are handled by
                        # `token_burn` alone.
                        if layout['recipient'] is None:
                            continue
                        realised.append(z.And(call['success'] == 1, call['target'] == asset,
                                              call['target'] != zero,
                                              selector == z.BitVecVal(code, selector.size()),
                                              arguments[layout['amount']] == amount,
                                              arguments[layout['recipient']] == recipient))
                    if not known_interface:
                        # Only undecodable when the call may actually be the declared asset's contract: a
                        # call to some other address cannot have moved this asset whatever its selector.
                        probe_target = z.Solver(); probe_target.set(timeout=100)
                        probe_target.add(*getattr(state, 'conditions', []))
                        probe_target.add(call['success'] == 1, call['target'] == asset, call['target'] != zero)
                        if probe_target.check() == z.sat:
                            unavailable = True
                if 'token_burn' in satisfiers and amount is not None:
                    # Destroying balance is a movement only inside the asset contract, so the call must go
                    # to the declared asset and carry a burn interface with the declared amount.
                    selector = call.get('input_selector')
                    arguments = call.get('input_words') or []
                    if selector is None or len(arguments) < 3:
                        unavailable = True
                        continue
                    for code, layout in Engine.TOKEN_INTERFACES.items():
                        if layout['recipient'] is not None:
                            continue
                        realised.append(z.And(call['success'] == 1, call['target'] == asset,
                                              call['target'] != zero,
                                              selector == z.BitVecVal(code, selector.size()),
                                              arguments[layout['amount']] == amount))
                if 'token_pull' in satisfiers and amount is not None:
                    # A custodial deposit moves the source's tokens to this contract. Transferring to some
                    # other payee is not a deposit.
                    selector = call.get('input_selector')
                    arguments = call.get('input_words') or []
                    if selector is None or len(arguments) < 3:
                        unavailable = True
                        continue
                    pull = Engine.TOKEN_INTERFACES[0x23b872dd]
                    terms = [call['success'] == 1, call['target'] == asset, call['target'] != zero,
                             selector == z.BitVecVal(0x23b872dd, selector.size()),
                             arguments[pull['amount']] == amount,
                             arguments[pull['recipient']] == self.address]
                    if source is not None:
                        terms.append(arguments[0] == source)
                    realised.append(z.And(*terms))
                if 'asset_call' in satisfiers:
                    # Legacy weak satisfier, kept only when a policy asks for it by name. It says that some
                    # contract other than the recipient was called, which is not evidence of movement.
                    realised.append(z.And(call['success'] == 1, call['target'] != recipient, call['target'] != zero))
            if 'allowance_write' in satisfiers:
                terms, undecidable = self._allowance_realisation(state, log, binding, words)
                realised.extend(terms)
                unavailable = unavailable or undecidable
            if 'custodial_deposit' in satisfiers:
                terms, undecidable = self._custodial_deposit_realisation(state, log, binding, words)
                realised.extend(terms)
                unavailable = unavailable or undecidable
            rows.append((z.And(declared, z.Not(z.Or(*realised)) if realised else z.BoolVal(True)), unavailable))
        if not rows:
            return z.BoolVal(False), False
        return z.Or(*[row[0] for row in rows]), any(row[1] for row in rows)

    def storage_hash_constraints(self,state):
        """Optional ideal-storage assumption: observed hashed keys do not equal fixed layout slots.

        Hash injectivity between observed preimages alone still permits keccak(holder, balancesSlot)
        to equal the totalSupply slot. Such a model fabricated a burnFrom authorization violation.
        This computational preimage assumption is explicit and separately configurable.
        """
        if not self.config.get('storage_hash_separation'):
            return []
        fixed={number(key) for _,key,_ in state.reads+state.writes if z.is_bv_value(simple(key))}
        # Mapping roots are fixed layout slots too, even if the path only accesses their hashed entries.
        fixed.update(number(parts[1]) for count,parts,_ in state.apps
                     if count==64 and len(parts)==2 and z.is_bv_value(simple(parts[1])))
        return [value!=bv(slot) for _,_,value in state.apps for slot in sorted(fixed)]

    def check(self):
        obligations=[]
        if self.policy.get('authorization'):obligations.append('authorization')
        if self.policy.get('token_debit'):obligations.append('token_debit_authority')
        if self.policy.get('replay'):obligations.extend(['nonce_consumption','consumed_message_rejection'])
        if self.policy.get('payout_event'):obligations.append('failed_call_event')
        if self.policy.get('failure_replay'):obligations.append('replay_after_failed_effect')
        if self.policy.get('movement_binding'):obligations.append('declared_movement')
        if self.policy.get('replay',{}).get('untrusted_callback_possible'):obligations.append('reentrant_replay')
        # The obligation phase needs its own deadline. `wall_seconds` bounds the *exploration*, so a contract that
        # explores quickly can still spend unbounded time here: the movement obligation issues a solver call and a
        # structural key walk per storage write per candidate log, and on the larger routers that ran for hours
        # while the row budget reported a timeout. Truncating is recorded, never silent.
        check_started=time.monotonic()
        check_budget=float(self.config.get('check_wall_seconds',self.config['wall_seconds']))
        # Switch the phase so `query` measures solver calls against the *checking* budget. Without this, an
        # exploration that consumed its own budget silences the checker even though `check_wall_seconds` is
        # untouched: every query is then refused and a decidable path is reported undecided.
        self.phase='checking'
        self.deadline=check_started+check_budget
        self.statistics['check_truncated_states']=0
        self.statistics['check_budget_seconds']=int(check_budget)
        try:
            return self._check_obligations(obligations,check_started,check_budget)
        finally:
            self.phase='finished'

    def _check_obligations(self,obligations,check_started,check_budget):
        results=[]
        for obligation in obligations:
            if obligation=='reentrant_replay':
                results.append({'obligation':obligation,'status':'unknown',
                                'reason':'callback state transitions are not modeled in v0.1; a reentrant verdict requires a supported callback path','witnesses':[]})
                continue
            witnesses=[];solver_unknown=False;positive=False;imprecise=False;scoped=False;guarded=False
            declaration_seen=False
            remaining=0
            for index,state in enumerate(self.finished):
                if self.check_expired(check_started,check_budget,index):
                    # Everything not yet examined is unresolved. Reporting this as a verdict would be a
                    # strength the analysis does not have, so the obligation becomes `unknown` with the count.
                    remaining=len(self.finished)-index
                    self.statistics['check_truncated_states']+=remaining
                    imprecise=True
                    break
                effects=self.effects(state)
                condition=effects;conditions=[]
                if obligation=='authorization':
                    slot=self.policy['authorization']['owner_slot'];owner=z.Select(self.initial_storage,bv(slot))&bv((1<<160)-1)
                    condition=z.And(effects,self.caller!=owner)
                elif obligation=='token_debit_authority':
                    from .token_authority import debit_condition
                    condition,has_debit,unavailable,_=debit_condition(self,state,self.policy['token_debit'])
                    scoped |= has_debit
                    if unavailable:
                        imprecise=True
                        continue
                    if not has_debit:
                        continue
                elif obligation in ['nonce_consumption','consumed_message_rejection']:
                    policy=self.policy['replay'];key,conditions=self.policy_key(state,policy);mask=bv(policy.get('mask',255))
                    initial=z.Select(self.initial_storage,key)&mask;final=z.Select(state.storage,key)&mask
                    if obligation=='nonce_consumption':
                        # Consumption and rejection are separate obligations. A missing read alone
                        # proves neither a feasible effect nor a missing consumption transition.
                        # Both obligations pass through precision checks and the solver below.
                        condition=z.And(effects,initial==bv(0),final==bv(0))
                    else:condition=z.And(effects,initial!=bv(0))
                elif obligation=='replay_after_failed_effect':
                    policy=self.policy['replay'];key,conditions=self.policy_key(state,policy);mask=bv(policy.get('mask',255))
                    scope=self.policy['failure_replay'].get('scope','self_call')
                    attempted=[call for call in state.calls
                               if scope!='self_call' or simple(call['target'])==simple(self.address)]
                    if not attempted:continue
                    scoped=True
                    final=z.Select(state.storage,key)&mask
                    condition=z.And(z.Or(*[call['success']==0 for call in attempted]),final==bv(0))
                elif obligation=='failed_call_event':
                    candidates=[];signature=int(self.policy['payout_event']['topic'],16)
                    for call in state.calls:
                        for log in state.logs:
                            if len(log['topics'])<2 or log['path_index']<call['path_index']:continue
                            candidates.append(z.And(call['success']==0,z.UGT(call['value'],bv(0)),log['topics'][0]==bv(signature),
                                                    log['topics'][1]==call['target'],log['length']==bv(32),log['first_word']==call['value']))
                    condition=z.Or(*candidates)
                elif obligation=='declared_movement':
                    binding=self.policy['movement_binding']
                    condition,movement_unavailable=self.declared_movement_mismatch(state,binding)
                    # Whether the declaring log is on this path is decided before the satisfier is
                    # consulted. Without that order an unresolvable satisfier skips the assignment and the
                    # obligation is reported as `not_applicable` -- "this entry has nothing to check" --
                    # when in fact it has something to check that the model cannot bind. Such a path must
                    # leave the obligation `unknown`.
                    signature_word=z.BitVecVal(int(binding['topic'],16),256)
                    if any(simple(log['topics'][0])==signature_word for log in state.logs if log['topics']):
                        declaration_seen=True
                    if movement_unavailable:
                        # A satisfier could not be constructed (no selector, an unmodelled interface, a
                        # declared slot the key does not expose). The path supports neither a violation
                        # nor a clean result.
                        imprecise=True;continue
                if state.abstracted and obligation!='authorization':
                    # A key or payload derived from abstracted memory cannot be matched to the policy
                    # key, so this path supports neither a violation nor a clean bill of health.
                    imprecise=True;continue
                if self.contaminated(state,condition):
                    imprecise=True;continue
                base=state.conditions+conditions+self.storage_hash_constraints(state)
                if self.config.get('storage_hash_separation'):
                    from .storage_model import reduce_storage
                    base=[reduce_storage(item) for item in base]
                    condition=reduce_storage(condition)
                answer,solver=self.query(base+[condition])
                if answer==z.sat:
                    witnesses.append(self.evidence(state,solver,obligation));break
                if answer==z.unknown:solver_unknown=True
                if obligation=='replay_after_failed_effect':
                    # Reaching a scoped attempt is the precondition; a value-call effect is not required.
                    positive=True;continue
                answer,_=self.query(base+[effects])
                positive |= answer==z.sat
                solver_unknown |= answer==z.unknown
            if obligation=='token_debit_authority' and not witnesses and not scoped:
                uncertain=bool(remaining or self.unknown or imprecise or solver_unknown)
                results.append({'obligation':obligation,'status':'unknown' if uncertain else 'not_applicable',
                                'reason':('balance debit scope could not be established' if uncertain else
                                          'no supported completed path writes the declared balance mapping'),
                                'witnesses':[]})
                continue
            if obligation=='replay_after_failed_effect' and not witnesses and not scoped:
                results.append({'obligation':obligation,
                                'status':'unknown' if remaining else 'not_applicable',
                                'reason':('the obligation deadline was reached before the completed paths were '
                                          'examined, so no self-call effect could be ruled out'
                                          if remaining else
                                          'no self-call effect was attempted on any completed path'),
                                'truncated_paths':remaining,'witnesses':[]})
                continue
            if obligation=='declared_movement' and not witnesses and not declaration_seen:
                if remaining:
                    # A truncated check cannot establish that no path declares the movement. Reporting
                    # `not_applicable` here would say "nothing to check", which is false: there is something to
                    # check and it was not examined.
                    results.append({'obligation':obligation,'status':'unknown',
                                    'reason':('the obligation deadline of %.0f s was reached after %d of %d '
                                              'completed path(s) were examined, so the absence of the declaring '
                                              'log is not established'
                                              %(check_budget,len(self.finished)-remaining,len(self.finished))),
                                    'truncated_paths':remaining,'witnesses':[]})
                elif self.unknown:
                    results.append({'obligation':obligation,'status':'unknown',
                                    'reason':('no explored path emits the declaring log, but %d path(s) were '
                                              'left unresolved, so the absence of the declaration is not '
                                              'established'%len(self.unknown)),
                                    'witnesses':[]})
                else:
                    results.append({'obligation':obligation,'status':'not_applicable',
                                    'reason':('no explored path emits the declaring log, so this entry cannot '
                                              'make the declaration the rule is about'),
                                    'witnesses':[]})
                continue
            if obligation=='authorization' and self.policy['authorization'].get('require_gate_evidence'):
                # Only applied to policies whose owner slot was inferred. When an analyst declares that
                # an effect must be gated, an absent gate is the finding, so no evidence is required.
                # Missing evidence of a gate leaves an inferred policy's applicability unresolved.
                # It must not classify an entry as permissionless or prove a clean result. A gate
                # could lie on an unexplored path or use a role model this policy does not express.
                slot=self.policy['authorization']['owner_slot']
                owner=z.Select(self.initial_storage,bv(slot))&bv((1<<160)-1)
                gate_seen=False
                gate_solver_unknown=False
                for state in self.reverted:
                    answer,_=self.query(state.conditions+[self.caller==owner])
                    if answer==z.unsat:
                        gate_seen=True;break
                    gate_solver_unknown |= answer==z.unknown
                if not gate_seen:
                    # A mechanism this policy does not model may still gate the function, so the honest
                    # verdict is "no gate evidence", not "permissionless".
                    reason=('no explored path reverts because the caller is not the owner of the inferred slot, '
                            'so the analysis has no evidence that this entry is meant to be gated')
                    if self.unknown or solver_unknown:
                        reason+=('; %d unsupported branch(es) and %d inconclusive solver query/queries were left '
                                 'unresolved, so an unmodelled gate such as a role mapping cannot be excluded'
                                 % (len(self.unknown), self.statistics['solver_unknown']))
                    if remaining:
                        reason=('the obligation deadline of %.0f s was reached before the reverted paths were '
                                'examined, so no gate evidence could be collected'%check_budget)
                    results.append({'obligation':obligation,'status':'unknown',
                                    'reason':reason,
                                    'policy_applicability':'unresolved',
                                    'truncated_paths':remaining,
                                    'gate_solver_unknown':gate_solver_unknown,'witnesses':[]})
                    continue
            status='violation' if witnesses else 'unknown' if (self.unknown or solver_unknown or imprecise or not positive) else 'supported_in_bounded_model'
            entry={'obligation':obligation,'status':status,'witnesses':witnesses}
            if obligation=='declared_movement' and status=='unknown':
                if self.unknown or solver_unknown:
                    entry['reason']=('%d unsupported branch(es) and %d inconclusive solver query/queries were '
                                     'left unresolved, so the declared movement could not be classified'
                                     %(len(self.unknown), self.statistics['solver_unknown']))
                elif imprecise:
                    entry['reason']='memory or payload precision was insufficient to classify the declared movement'
                elif not positive:
                    entry['reason']=('the declaring log was reached, but no supported satisfier established '
                                     'the corresponding asset movement')
            if remaining:
                # A witness found before the deadline is still evidence and keeps its status; the truncation is
                # additive information, never a downgrade of what was already established.
                entry['truncated_paths']=remaining
                if status!='violation':
                    entry['reason']=('%d path(s) were not examined because the obligation deadline of %.0f s was '
                                     'reached, so neither a violation nor a clean result is established'
                                     %(remaining,check_budget))
            elif status=='unknown' and imprecise and not (self.unknown or solver_unknown or not positive):
                entry['reason']='memory abstracted on all committing paths; key/payload precision insufficient'
            results.append(entry)
        return {'schema':'enforcement-v0.1','policy':self.policy,'obligations':results,'unknown_paths':self.unknown,
                'bounded_unrolls':len(self.unrolled),
                'statistics':dict(self.statistics),'elapsed_seconds':time.monotonic()-self.started,
                'config':self.config,'facts':self.facts.summary(),'solver_version':z.get_version_string(),
                'scope':['Bounded supported TAC paths and one transaction; arbitrary initial storage.',
                         'Ideal-hash abstraction for observed preimages; explicit ABI/protocol policy.',
                         ('Observed hash outputs separated from fixed storage slots (computational preimage assumption).'
                          if self.config.get('storage_hash_separation') else
                          'Hash outputs are not separated from fixed storage slots in this variant.'),
                         'External call success/return bytes abstracted; no reentrant state changes or gas model.',
                         'Unknowns and unsupported IR remain visible; no global EVM safety proof.'],
                'benchmark_metrics':None}
