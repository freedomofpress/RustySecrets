use gf256::Gf256;

/// Evaluates an interpolated polynomial at `Gf256::zero()` where
/// the polynomial is determined using barycentric Lagrange
/// interpolation based on the given `points` in
/// the G(2^8) Galois field.
pub(crate) fn interpolate_at(k: u8, points: &[(u8, u8)]) -> u8 {
    barycentric_interpolate_at(k as usize, points)
}

/// Barycentric Lagrange interpolation algorithm from "Polynomial
/// Interpolation: Langrange vs Newton" by Wilhelm Werner. Evaluates
/// the polynomial at `Gf256::zero()`.
#[inline]
fn barycentric_interpolate_at(k: usize, points: &[(u8, u8)]) -> u8 {
    // Compute the barycentric weights `w`.
    let mut w = vec![Gf256::zero(); k];
    w[0] = Gf256::one();

    let mut x = Vec::with_capacity(k);
    x.push(Gf256::from_byte(points[0].0));

    for i in 1..k {
        x.push(Gf256::from_byte(points[i].0));
        for j in 0..i {
            let delta = x[j] - x[i];
            assert_ne!(delta.poly, 0, "Duplicate shares");
            w[j] /= delta;
            w[i] -= w[j];
        }
    }

    // Evaluate the second or "true" form of the barycentric
    // interpolation formula at `Gf256::zero()`.
    let (mut num, mut denom) = (Gf256::zero(), Gf256::zero());
    for i in 0..k {
        assert_ne!(x[i].poly, 0, "Invalid share x = 0");
        let diff = w[i] / x[i];
        num += diff * Gf256::from_byte(points[i].1);
        denom += diff;
    }

    (num / denom).to_byte()
}
