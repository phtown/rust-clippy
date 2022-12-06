// run-rustfix
// edition:2018
// aux-build:macro_rules.rs

#![feature(exclusive_range_pattern)]
#![feature(stmt_expr_attributes)]
#![warn(clippy::almost_complete_digit_range)]
#![allow(ellipsis_inclusive_range_patterns)]
#![allow(clippy::needless_parens_on_range_literals)]

#[macro_use]
extern crate macro_rules;

macro_rules! zero {
    () => {
        '0'
    };
}

macro_rules! b {
    () => {
        let _ = '0'..'9';
    };
}

fn main() {
    #[rustfmt::skip]
    {
        let _ = ('0') ..'9';
        let _ = '0' .. ('9');
        let _ = ('0') .. ('9');
    }

    let _ = '1'..'9';

    let _ = (b'0')..(b'9');
    let _ = b'0'..b'9';

    let _ = b'1'..b'9';

    let _ = zero!()..'9';

    let _ = match 0u8 {
        b'0'..b'9' if true => 1,
        b'1'..b'9' => 3,
        _ => 5,
    };
    let _ = match '8' {
        '0'..'9' if true => 1,
        '1'..'9' => 3,
        _ => 5,
    };

    almost_complete_digit_range!();
    b!();
}

#[clippy::msrv = "1.25"]
fn _under_msrv() {
    let _ = match '0' {
        '0'..'9' => 1,
        _ => 2,
    };
}

#[clippy::msrv = "1.26"]
fn _meets_msrv() {
    let _ = '0'..'9';
    let _ = match '0' {
        '0'..'9' => 1,
        _ => 2,
    };
}
