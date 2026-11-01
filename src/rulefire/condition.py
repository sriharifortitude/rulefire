"""The condition expression: and, or, not, parentheses, and `1 of` / `all of` a set of selections."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from dataclasses import dataclass

from rulefire.values import RuleError


@dataclass(frozen=True)
class Ref:
    name: str


@dataclass(frozen=True)
class Not:
    arg: Node


@dataclass(frozen=True)
class And:
    args: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    args: tuple[Node, ...]


Node = Ref | Not | And | Or

_TOKEN = re.compile(r"\s*(\(|\)|[^\s()]+)")


def tokenize(text: str) -> list[str]:
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            break
        out.append(m.group(1))
        pos = m.end()
    return out


def parse(text: str, names: list[str]) -> Node:
    """Parses a condition over the given selection names. `1 of x*` becomes an Or of the
    selections the pattern matches; `them` means every selection not starting with "_"."""
    if "|" in text:
        raise RuleError("aggregations after | (count, near, ...) are not supported")
    p = _Parser(tokenize(text), names)
    node = p.expr()
    if p.pos != len(p.tokens):
        raise RuleError(f"unexpected {p.tokens[p.pos]!r} in condition {text!r}")
    return node


class _Parser:
    def __init__(self, tokens: list[str], names: list[str]) -> None:
        self.tokens = tokens
        self.names = names
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        t = self.peek()
        if t is None:
            raise RuleError("the condition ends too early")
        self.pos += 1
        return t

    def expr(self) -> Node:
        args = [self.term()]
        while (t := self.peek()) is not None and t.lower() == "or":
            self.take()
            args.append(self.term())
        return args[0] if len(args) == 1 else Or(tuple(args))

    def term(self) -> Node:
        args = [self.factor()]
        while (t := self.peek()) is not None and t.lower() == "and":
            self.take()
            args.append(self.factor())
        return args[0] if len(args) == 1 else And(tuple(args))

    def factor(self) -> Node:
        t = self.take()
        low = t.lower()
        if low == "not":
            return Not(self.factor())
        if t == "(":
            node = self.expr()
            if self.take() != ")":
                raise RuleError("a ( without its )")
            return node
        if low in ("1", "any", "all") and (n := self.peek()) is not None and n.lower() == "of":
            self.take()
            target = self.take()
            if target.lower() == "them":
                chosen = [n for n in self.names if not n.startswith("_")]
            else:
                chosen = [n for n in self.names if fnmatch.fnmatchcase(n, target)]
            if not chosen:
                raise RuleError(f"{t} of {target} matches no selection")
            refs = tuple(Ref(n) for n in chosen)
            if len(refs) == 1:
                return refs[0]
            return And(refs) if low == "all" else Or(refs)
        if low in ("and", "or", ")", "of"):
            raise RuleError(f"unexpected {t!r} in condition")
        if t not in self.names:
            raise RuleError(f"the condition names {t!r}, which is not a selection")
        return Ref(t)


def evaluate(node: Node, selection: Callable[[str], bool]) -> bool:
    if isinstance(node, Ref):
        return selection(node.name)
    if isinstance(node, Not):
        return not evaluate(node.arg, selection)
    if isinstance(node, And):
        return all(evaluate(a, selection) for a in node.args)
    return any(evaluate(a, selection) for a in node.args)


def referenced(node: Node) -> set[str]:
    if isinstance(node, Ref):
        return {node.name}
    if isinstance(node, Not):
        return referenced(node.arg)
    return set().union(*(referenced(a) for a in node.args))
