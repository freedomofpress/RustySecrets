#![allow(suspicious_arithmetic_impl)]

//! This module provides the Gf256 type which is used to represent
//! elements of a finite field with 256 elements.

use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

include!(concat!(env!("OUT_DIR"), "/nothinghardcoded.rs"));

fn get_tables() -> &'static Tables {
    &TABLES
}

/// Type for elements of a finite field with 256 elements
#[derive(Copy, Debug, Clone, PartialEq, Eq)]
pub struct Gf256 {
    pub poly: u8,
}

impl Gf256 {
    /// returns the additive neutral element of the field
    #[inline]
    pub fn zero() -> Gf256 {
        Gf256 { poly: 0 }
    }

    /// returns the multiplicative neutral element of the field
    #[inline]
    pub fn one() -> Gf256 {
        Gf256 { poly: 1 }
    }

    #[inline]
    pub fn from_byte(b: u8) -> Gf256 {
        Gf256 { poly: b }
    }

    #[inline]
    pub fn to_byte(self) -> u8 {
        self.poly
    }

    pub fn exp(power: u8) -> Gf256 {
        let tabs = get_tables();
        Gf256::from_byte(tabs.exp[power as usize])
    }

    pub fn log(self) -> Option<u8> {
        if self.poly == 0 {
            None
        } else {
            let tabs = get_tables();
            Some(tabs.log[self.poly as usize])
        }
    }

    #[allow(dead_code)]
    pub fn pow(self, mut exp: u8) -> Gf256 {
        let mut base = self;
        let mut acc = Self::one();

        while exp > 1 {
            if (exp & 1) == 1 {
                acc *= base;
            }
            exp /= 2;
            base = base * base;
        }

        if exp == 1 {
            acc *= base;
        }

        acc
    }
}

impl Add<Gf256> for Gf256 {
    type Output = Gf256;
    #[inline]
    fn add(self, rhs: Gf256) -> Gf256 {
        Gf256::from_byte(self.poly ^ rhs.poly)
    }
}

impl AddAssign<Gf256> for Gf256 {
    #[inline]
    fn add_assign(&mut self, rhs: Gf256) {
        *self = *self + rhs;
    }
}

impl Sub<Gf256> for Gf256 {
    type Output = Gf256;
    #[inline]
    fn sub(self, rhs: Gf256) -> Gf256 {
        Gf256::from_byte(self.poly ^ rhs.poly)
    }
}

impl SubAssign<Gf256> for Gf256 {
    #[inline]
    fn sub_assign(&mut self, rhs: Gf256) {
        *self = *self - rhs;
    }
}

impl Mul<Gf256> for Gf256 {
    type Output = Gf256;
    fn mul(self, rhs: Gf256) -> Gf256 {
        if let (Some(l1), Some(l2)) = (self.log(), rhs.log()) {
            let tmp = (u16::from(l1) + u16::from(l2)) % 255;
            Gf256::exp(tmp as u8)
        } else {
            Gf256 { poly: 0 }
        }
    }
}

impl MulAssign<Gf256> for Gf256 {
    fn mul_assign(&mut self, rhs: Gf256) {
        *self = *self * rhs;
    }
}

impl Div<Gf256> for Gf256 {
    type Output = Gf256;
    fn div(self, rhs: Gf256) -> Gf256 {
        let l2 = rhs.log().expect("division by zero");
        if let Some(l1) = self.log() {
            let tmp = (u16::from(l1) + 255 - u16::from(l2)) % 255;
            Gf256::exp(tmp as u8)
        } else {
            Gf256 { poly: 0 }
        }
    }
}

impl DivAssign<Gf256> for Gf256 {
    fn div_assign(&mut self, rhs: Gf256) {
        *self = *self / rhs;
    }
}

impl Neg for Gf256 {
    type Output = Gf256;
    fn neg(self) -> Gf256 {
        Gf256::zero() - self
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! gf256 {
    ($e:expr) => {
        Gf256::from_byte($e)
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! gf256_vec {
    ( $( ($x:expr, $y:expr) ),* ) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push((Gf256::from_byte($x), Gf256::from_byte($y)));
            )*
            temp_vec
        }
    };
    ( $( $x:expr ),* ) => {
        {
            let mut temp_vec = Vec::new();
            $(
                temp_vec.push(Gf256::from_byte($x));
            )*
            temp_vec
        }
    };
}

#[cfg(test)]
#[allow(trivial_casts)]
mod tests {

    use super::*;
    use quickcheck::*;

    mod vectors {
        use super::*;
        use flate2::read::GzDecoder;
        use itertools::Itertools;
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        macro_rules! mk_test {
            ($id:ident, $op:expr, $val:expr) => {
                mk_test!($id, $op, $val, 0);
            };
            ($id:ident, $op:expr, $val:expr, $y:expr) => {
                #[test]
                fn $id() {
                    let results = (0..256).cartesian_product($y..256).map(|(i, j)| {
                        let (i, j) = (Gf256::from_byte(i as u8), Gf256::from_byte(j as u8));
                        (i.to_byte(), j.to_byte(), $val(i, j).to_byte())
                    });

                    let ref_path = format!("tests/fixtures/gf256/gf256_{}.txt.gz", stringify!($id));
                    let reference =
                        BufReader::new(GzDecoder::new(File::open(ref_path).unwrap()).unwrap());

                    for ((i, j, k), line) in results.zip(reference.lines()) {
                        let left = format!("{} {} {} = {}", i, $op, j, k);
                        let right = line.unwrap();
                        assert_eq!(left, right);
                    }
                }
            };
        }

        mk_test!(add, "+", |i: Gf256, j: Gf256| i + j);
        mk_test!(sub, "-", |i: Gf256, j: Gf256| i - j);
        mk_test!(mul, "*", |i: Gf256, j: Gf256| i * j);
        mk_test!(div, "/", |i: Gf256, j: Gf256| i.div(j), 1);
        mk_test!(pow, "^", |i: Gf256, j: Gf256| i.pow(j.to_byte()));
    }

    impl Arbitrary for Gf256 {
        fn arbitrary<G: Gen>(gen: &mut G) -> Gf256 {
            Gf256::from_byte(u8::arbitrary(gen))
        }
    }

    mod addition {
        use super::*;

        quickcheck! {
            fn law_associativity(a: Gf256, b: Gf256, c: Gf256) -> bool {
                (a + b) + c == a + (b + c)
            }

            #[cfg_attr(feature = "cargo-clippy", allow(eq_op))]
            fn law_commutativity(a: Gf256, b: Gf256) -> bool {
                a + b == b + a
            }

            fn law_distributivity(a: Gf256, b: Gf256, c: Gf256) -> bool {
                a * (b + c) == a * b + a * c
            }

            fn law_identity(a: Gf256) -> bool {
                a + Gf256::zero() == a && Gf256::zero() + a == a
            }

            fn law_inverses(a: Gf256) -> bool {
                a + (-a) == Gf256::zero() && (-a) + a == Gf256::zero()
            }
        }
    }

    mod multiplication {
        use super::*;

        quickcheck! {
            fn law_associativity(a: Gf256, b: Gf256, c: Gf256) -> bool {
                (a * b) * c == a * (b * c)
            }

            #[cfg_attr(feature = "cargo-clippy", allow(eq_op))]
            fn law_commutativity(a: Gf256, b: Gf256) -> bool {
                a * b == b * a
            }

            fn law_distributivity(a: Gf256, b: Gf256, c: Gf256) -> bool {
                (a + b) * c == a * c + b * c
            }

            fn law_identity(a: Gf256) -> bool {
                a * Gf256::one() == a && Gf256::one() * a == a
            }

            fn law_inverses(a: Gf256) -> TestResult {
                if a == Gf256::zero() {
                    return TestResult::discard();
                }

                let left = a * (Gf256::one() / a) == Gf256::one();
                let right = (Gf256::one() / a) * a == Gf256::one();

                TestResult::from_bool(left && right)
            }
        }

    }

}
