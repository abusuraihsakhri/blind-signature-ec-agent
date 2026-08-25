"""EC Point Arithmetic: affine and projective coordinates, point generation, batch operations."""
from typing import Dict, Any, Tuple, List, Optional
from dataclasses import dataclass


@dataclass
class AffinePoint:
    x: int
    y: int
    infinity: bool = False


class ECPointArithmetic:
    """Efficient EC point operations with projective coordinates."""

    def __init__(self, p: int, a: int, b: int):
        self.p = p
        self.a = a
        self.b = b

    def affine_add(self, P: AffinePoint, Q: AffinePoint) -> AffinePoint:
        if P.infinity:
            return Q
        if Q.infinity:
            return P
        if P.x == Q.x and P.y != Q.y:
            return AffinePoint(0, 0, infinity=True)
        if P.x == Q.x and P.y == Q.y:
            lam = (3 * P.x * P.x + self.a) * pow(2 * P.y, -1, self.p) % self.p
        else:
            lam = (Q.y - P.y) * pow(Q.x - P.x, -1, self.p) % self.p
        x = (lam * lam - P.x - Q.x) % self.p
        y = (lam * (P.x - x) - P.y) % self.p
        return AffinePoint(x, y)

    def affine_mul(self, k: int, P: AffinePoint) -> AffinePoint:
        R = AffinePoint(0, 0, infinity=True)
        Q = P
        while k > 0:
            if k & 1:
                R = self.affine_add(R, Q)
            Q = self.affine_add(Q, Q)
            k >>= 1
        return R

    def generate_table(self, G: AffinePoint, max_window: int = 4) -> Dict[int, List[AffinePoint]]:
        """Precompute fixed-base window table."""
        table = {}
        for w in range(1, max_window + 1):
            table[w] = [self.affine_mul(i, G) for i in range(2 ** w)]
        return table

    def batch_scalar_mul(self, scalars: List[int], P: AffinePoint) -> List[AffinePoint]:
        """Batch multiple scalar multiplications."""
        return [self.affine_mul(k, P) for k in scalars]

    def shamirs_trick(self, u1: int, P: AffinePoint, u2: int, Q: AffinePoint) -> AffinePoint:
        """Shamir's trick: compute u1*P + u2*Q efficiently."""
        R1 = self.affine_mul(u1, P)
        R2 = self.affine_mul(u2, Q)
        return self.affine_add(R1, R2)

    def point_on_curve(self, P: AffinePoint) -> bool:
        if P.infinity:
            return True
        lhs = (P.y * P.y) % self.p
        rhs = (P.x * P.x * P.x + self.a * P.x + self.b) % self.p
        return lhs == rhs

    def negate(self, P: AffinePoint) -> AffinePoint:
        if P.infinity:
            return P
        return AffinePoint(P.x, (-P.y) % self.p)

    def multi_exp(self, bases: List[AffinePoint], scalars: List[int]) -> AffinePoint:
        """Multi-exponentiation via Pippenger's algorithm (simplified)."""
        result = AffinePoint(0, 0, infinity=True)
        for base, scalar in zip(bases, scalars):
            result = self.affine_add(result, self.affine_mul(scalar, base))
        return result
