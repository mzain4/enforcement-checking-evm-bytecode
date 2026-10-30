"""Read one Gigahorse generation; instruction order/CFG from its TAC, values from its facts."""
from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import re


@dataclass
class Instruction:
    id: str
    op: str
    uses: list[str]
    defines: list[str]


@dataclass
class Block:
    id: str
    function: str
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)
    instructions: list[Instruction] = field(default_factory=list)


class Facts:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.hashes = {}
        def relation(name, required=True):
            path = self.directory / (name + '.csv')
            if not path.exists():
                if required: raise ValueError('Missing relation: '+name)
                return []
            raw = path.read_bytes(); self.hashes[path.name] = hashlib.sha256(raw).hexdigest()
            return [line.split('\t') for line in raw.decode('utf8').splitlines() if line]
        ops = dict(relation('TAC_Op'))
        self.constants = {}
        for name,value in relation('TAC_Variable_Value'):
            try:self.constants[name] = int(value,16)
            except ValueError:pass
        uses,defs = {},{}
        for target,name in [(uses,'TAC_Use'),(defs,'TAC_Def')]:
            for instruction,var,index in relation(name):target.setdefault(instruction,[]).append((int(index),var))
        def arguments(mapping, key):
            rows=mapping.get(key,[])
            if ops[key]=='PHI' and rows and all(index==-1 for index,var in rows):
                return list(dict.fromkeys(var for index,var in rows))
            row=dict(rows)
            if len(row)!=len(rows):raise ValueError('Repeated positional operand index: '+key)
            if row and sorted(row)!=list(range(len(row))):raise ValueError('Noncontiguous operand indices: '+key)
            return [row[i] for i in range(len(row))]
        self.public = dict(relation('PublicFunction',False))
        self.function_names = dict(relation('HighLevelFunctionName',False))
        self.formal_arguments = {}
        for function, variable, index in relation('FormalArgs',False):
            self.formal_arguments.setdefault(function, {})[int(index)] = variable
        self.bytecode_sha256=None
        bytecode=self.directory/'bytecode.hex'
        if bytecode.is_file():
            code=re.sub(r'\s+','',bytecode.read_text()).removeprefix('0x')
            try:self.bytecode_sha256=hashlib.sha256(bytes.fromhex(code)).hexdigest()
            except ValueError:raise ValueError('Invalid bytecode input in facts')
        tac = self.directory/'contract.tac'; raw=tac.read_bytes()
        self.hashes['contract.tac']=hashlib.sha256(raw).hexdigest()
        self.blocks={};self.functions={};self.instructions={};function=None;block=None
        for line in raw.decode('utf8').splitlines():
            if line.startswith('function '):function=line[9:].split('(')[0]
            match=re.match(r'\s*Begin block (\S+)',line)
            if match:
                block=Block(match[1],function)
                if block.id in self.blocks:raise ValueError('Repeated block ID')
                self.blocks[block.id]=block;self.functions.setdefault(function,[]).append(block.id)
            match=re.search(r'prev=\[([^]]*)\],\s*succ=\[([^]]*)\]',line)
            if match and block is not None:
                block.predecessors=[s.strip() for s in match[1].split(',') if s.strip()]
                block.successors=[s.strip() for s in match[2].split(',') if s.strip()]
            match=re.match(r'\s+(\S+):\s',line)
            if match:
                key=match[1]
                if key not in ops:raise ValueError('TAC statement absent from operation facts: '+key)
                instruction=Instruction(key,ops[key],arguments(uses,key),arguments(defs,key))
                if key in self.instructions:raise ValueError('Repeated instruction ID')
                self.instructions[key]=instruction;block.instructions.append(instruction)
        self.entry=self.functions.get('__function_selector__',[None])[0]
        self.phi_twins={}
        for instruction in self.instructions.values():
            if instruction.op=='PHI' and len(instruction.defines)==1:
                self.phi_twins.setdefault(tuple(instruction.uses),[]).append(instruction.defines[0])
        self.return_positions={}
        for name,block_ids in self.functions.items():
            for block_id in block_ids:
                for instruction in self.blocks[block_id].instructions:
                    if instruction.op!='RETURNPRIVATE' or not instruction.uses:continue
                    for index,formal in self.formal_arguments.get(name,{}).items():
                        if formal==instruction.uses[0]:self.return_positions[name]=index
        self.unmapped_operations=sorted(set(ops)-set(self.instructions))
        self.missing_edges=[(b.id,s) for b in self.blocks.values() for s in b.successors if s not in self.blocks]
        if self.entry is None:raise ValueError('No dispatcher entry')

    @staticmethod
    def original_address(identifier):
        identifier=identifier.split('B0x')[0]
        clone=identifier.find('0x',2)
        if clone!=-1:identifier=identifier[:clone]
        match=re.fullmatch(r'0x([0-9a-fA-F]+)',identifier)
        return int(match[1],16) if match else None

    @staticmethod
    def identifier_parts(identifier):
        """Split a decompiler identifier into its hex components.

        Cloned TAC contexts concatenate components without a separator, so `0x4040x1dc0xdb` is three
        components rather than one malformed literal. A component never contains the substring `0x`, so
        splitting at every occurrence of `0x` is unambiguous. A `B` immediately before a following `0x` is
        the decompiler's block/clone separator and is removed from the preceding component; it is otherwise
        a hex digit and is preserved. The function never guesses a missing component.
        """
        if not identifier:
            return []
        chunks=[chunk for chunk in re.split(r'(?=0x)', str(identifier)) if chunk]
        parts=[]
        for index,chunk in enumerate(chunks):
            if index+1<len(chunks):
                chunk=chunk.rstrip('/')
                if chunk.endswith('B'):
                    chunk=chunk[:-1]
            parts.append(chunk)
        return parts

    @classmethod
    def canonical_identifier(cls, identifier):
        """A rendering in which every component is a valid hex literal, joined by `/`.

        `0x4040x1dc0xdb` becomes `0x404/0x1dc/0xdb` and `0xce5B0xe2` becomes `0xce5/0xe2`. The raw string
        is preserved beside it wherever a witness is written, so the repair cannot be mistaken for a
        semantic change.
        """
        if not identifier:
            return identifier
        return '/'.join(cls.identifier_parts(identifier))

    def resolve_target(self, block, value):
        # Prefer explicit CFG successors, preserving cloned contexts.
        candidates=[s for s in block.successors if self.original_address(s)==value]
        if len(candidates)==1:return candidates[0]
        exact=hex(value)
        if not candidates and exact in self.blocks:return exact
        raise ValueError('Ambiguous/unresolved jump target: '+block.id+' -> '+hex(value))

    @staticmethod
    def context_of(identifier):
        address=Facts.original_address(identifier)
        return None if address is None else identifier[len(hex(address)):]

    def resolve_in_context(self, caller, value):
        suffix=self.context_of(caller)
        for candidates in ([b for b in self.blocks if self.original_address(b)==value and self.context_of(b)==suffix],
                           [b for b in self.blocks if self.original_address(b)==value]):
            if len(candidates)==1:return candidates[0]
            if len(candidates)>1:raise ValueError('Ambiguous private-call target: '+caller+' -> '+hex(value))
        raise ValueError('Unresolved private-call target: '+caller+' -> '+hex(value))

    def resolve_return(self, caller, entry, resume, path=()):
        for suffix in (self.context_of(entry),self.context_of(caller)):
            candidates=[b for b in self.blocks if self.original_address(b)==resume and self.context_of(b)==suffix]
            if len(candidates)==1:return candidates[0]
        for visited in reversed(path):
            candidates=[b for b in self.blocks if self.original_address(b)==resume and self.context_of(b)==visited]
            if len(candidates)==1:return candidates[0]
        candidates=[b for b in self.blocks if self.original_address(b)==resume]
        if len(candidates)==1:return candidates[0]
        raise ValueError('Ambiguous/unresolved private-call return: '+caller+' -> '+hex(resume))

    def return_position(self, entry):
        address=self.original_address(entry)
        return self.return_positions.get(hex(address)) if address is not None else None

    def formal_bindings(self, entry):
        address=self.original_address(entry)
        rows=self.formal_arguments.get(hex(address),{}) if address is not None else {}
        if sorted(rows)!=list(range(len(rows))):raise ValueError('Noncontiguous formal arguments: '+entry)
        return [rows[index] for index in range(len(rows))]

    def display_name(self, function):
        """Readable name for a private/public function key, falling back to the key itself."""
        if function is None:return None
        name=self.function_names.get(function)
        if not name:return function
        # Prefer the signature-bearing name (e.g. `executed(uint256)`) over a bare `()`. 
        if name.endswith('()') and function in self.public:
            selector=self.public[function]
            for candidate in self.function_names.values():
                if candidate.startswith(selector.replace('0x','0x')):return candidate
        return name

    def function_of_block(self, block):
        entry=self.blocks.get(block)
        return entry.function if entry else None

    def block_of_instruction(self, instruction):
        for block in self.blocks.values():
            if any(item.id==instruction for item in block.instructions):return block.id
        return None

    def summary(self):
        return {'blocks':len(self.blocks),'instructions':len(self.instructions),'public_functions':len(self.public),                'bytecode_sha256':self.bytecode_sha256,
                'unmapped_operations':len(self.unmapped_operations),'missing_edges':self.missing_edges,
                'input_hashes':self.hashes}
