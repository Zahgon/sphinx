
use crate::constants::DELAY_LENGTH;
use byteorder::{BigEndian, ByteOrder};
use rand_distr::num_traits::Zero;
use rand_distr::{Distribution, Exp};
use std::{borrow::Borrow, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delay(u64);

impl Delay {
    
    pub const fn new_from_nanos(value: u64) -> Self {
        Delay(value)
    }

    pub const fn new_from_millis(value: u64) -> Self {
        const NANOS_PER_MILLI: u64 = 1_000_000;

        Self::new_from_nanos(NANOS_PER_MILLI * value)
    }

    pub fn to_nanos(&self) -> u64 { panic!("STUB: not implemented") }

    pub fn to_duration(&self) -> Duration { panic!("STUB: not implemented") }

    pub fn to_bytes(&self) -> [u8; DELAY_LENGTH] { panic!("STUB: not implemented") }

    pub fn from_bytes(delay_bytes: [u8; DELAY_LENGTH]) -> Self { panic!("STUB: not implemented") }
}

impl<T> std::iter::Sum<T> for Delay
where
    T: Borrow<Delay>,
{
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = T>,
    { panic!("STUB: not implemented") }
}

impl<T> std::ops::Add<T> for &Delay
where
    T: Borrow<Delay>,
{
    type Output = Delay;
    fn add(self, rhs: T) -> Self::Output { panic!("STUB: not implemented") }
}

impl<T> std::ops::Add<T> for Delay
where
    T: Borrow<Delay>,
{
    type Output = Delay;
    fn add(self, rhs: T) -> Self::Output { panic!("STUB: not implemented") }
}

impl std::ops::Mul<f64> for Delay {
    type Output = Delay;
    fn mul(self, rhs: f64) -> Self::Output { panic!("STUB: not implemented") }
}

pub fn generate_from_nanos(number: usize, average_delay: u64) -> Vec<Delay> { panic!("STUB: not implemented") }

pub fn generate_from_average_duration(number: usize, average_delay: Duration) -> Vec<Delay> { panic!("STUB: not implemented") }

fn generate_delays(number: usize, average_delay: f64) -> Vec<Delay> { panic!("STUB: not implemented") }

#[cfg(test)]
mod test_delay_generation {
    use super::*;

    #[test]
    fn with_0_delays_returns_an_empty_vector() {
        let delays = generate_from_average_duration(0, Duration::from_millis(10));
        assert_eq!(0, delays.len());
    }

    #[test]
    fn with_1_delay_it_returns_1_delay() {
        let delays = generate_from_average_duration(1, Duration::from_secs(1));
        assert_eq!(1, delays.len());
    }

    #[test]
    fn with_3_delays_it_returns_3_delays() {
        let delays = generate_from_average_duration(3, Duration::from_nanos(1));
        assert_eq!(3, delays.len());
    }

    #[test]
    fn it_is_possible_to_convert_it_to_and_from_bytes_without_data_loss() {
        let expected_delay_nanos = 1_234_567_890; 
        let delay = Delay::new_from_nanos(expected_delay_nanos);
        let delay_bytes = delay.to_bytes();
        let recovered_delay = Delay::from_bytes(delay_bytes);
        assert_eq!(delay, recovered_delay);
    }

    #[test]
    fn it_is_possible_to_convert_it_to_and_from_nanos_without_data_loss() {
        let expected_delay_nanos = 1_234_567_890; 
        let delay = Delay::new_from_nanos(expected_delay_nanos);
        assert_eq!(expected_delay_nanos, delay.to_nanos());
    }

    #[test]
    fn it_is_possible_to_convert_it_to_and_from_duration_without_data_loss() {
        let expected_delay_nanos = 1_234_567_890; 
        let delay = Delay::new_from_nanos(expected_delay_nanos);
        let delay_duration = delay.to_duration();
        assert_eq!(Duration::from_nanos(expected_delay_nanos), delay_duration);
    }
}

#[cfg(test)]
mod delay_summing {
    use super::*;

    #[test]
    fn works_with_std_ops_only() {
        let delay1 = Delay(42);
        let delay2 = Delay(123);

        let expected1 = Delay(165);
        assert_eq!(expected1, delay1 + delay2);

        let expected2 = Delay(265);
        let delay3 = Delay(100);
        assert_eq!(expected2, delay1 + delay2 + delay3)
    }

    #[test]
    fn works_with_iterator() {
        let delays = [Delay(42), Delay(123), Delay(100)];
        let expected = Delay(265);

        assert_eq!(expected, delays.iter().sum());
        assert_eq!(Delay(0), Vec::new().iter().sum())
    }
}
