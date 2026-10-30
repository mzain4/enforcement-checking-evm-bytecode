"""Storage-expression reduction under the explicitly enabled ideal layout assumption.

Different mapping roots and fixed slots occupy separate storage families. Keys in
the SAME family may alias, so their stores are retained. No address, name or case
label participates. This is a computational hash assumption, not exact EVM theory.
"""
import z3 as z


def family(key):
    key = z.simplify(key)
    if z.is_bv_value(key):
        return ("fixed", key.as_long())
    if z.is_app(key) and key.decl().name() == "keccak_64" and key.num_args() == 2:
        inner = family(key.arg(1))
        if inner is not None:
            return ("mapping", inner[1])
    return None


def distinct_families(first, second):
    left, right = family(first), family(second)
    return left is not None and right is not None and left != right


def reduce_storage(expression):
    """Rewrite selects past provably separate layout families; preserve ambiguous aliases."""
    memo = {}

    def visit(node):
        identity = node.get_id()
        if identity in memo:
            return memo[identity]
        if not z.is_app(node) or not node.num_args():
            result = node
        else:
            children = [visit(child) for child in node.children()]
            result = node.decl()(*children)
            if z.is_select(result):
                array, key = result.children()
                while z.is_store(array):
                    previous, stored_key, value = array.children()
                    if z.eq(z.simplify(key), z.simplify(stored_key)):
                        result = value
                        break
                    if not distinct_families(key, stored_key):
                        result = z.Select(array, key)
                        break
                    array = previous
                    result = z.Select(array, key)
        memo[identity] = result
        return result

    return z.simplify(visit(expression))
