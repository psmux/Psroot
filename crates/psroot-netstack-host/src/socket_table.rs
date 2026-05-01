//! Table of per-container logical sockets.
//!
//! Sockets have opaque u32 ids independent of host OS handles. Ids are
//! allocated monotonically and recycled via a free list so long-running
//! containers don't exhaust u32 space.

use std::collections::VecDeque;

/// Generic table keyed by logical socket id. Backends parameterise `T`
/// with their own per-socket state.
pub struct SocketTable<T> {
    slots: Vec<Option<T>>,
    free: VecDeque<u32>,
    next_id: u32,
}

impl<T> Default for SocketTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SocketTable<T> {
    pub fn new() -> Self {
        // Reserve index 0 so id=0 can mean "none" on the wire.
        Self {
            slots: vec![None],
            free: VecDeque::new(),
            next_id: 1,
        }
    }

    pub fn insert(&mut self, value: T) -> u32 {
        if let Some(id) = self.free.pop_front() {
            self.slots[id as usize] = Some(value);
            return id;
        }
        let id = self.next_id;
        self.next_id = self
            .next_id
            .checked_add(1)
            .expect("socket id space exhausted");
        self.slots.push(Some(value));
        id
    }

    pub fn get(&self, id: u32) -> Option<&T> {
        self.slots.get(id as usize).and_then(|s| s.as_ref())
    }

    pub fn get_mut(&mut self, id: u32) -> Option<&mut T> {
        self.slots.get_mut(id as usize).and_then(|s| s.as_mut())
    }

    pub fn remove(&mut self, id: u32) -> Option<T> {
        let v = self.slots.get_mut(id as usize).and_then(|s| s.take());
        if v.is_some() {
            self.free.push_back(id);
        }
        v
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut t: SocketTable<&'static str> = SocketTable::new();
        let a = t.insert("alpha");
        let b = t.insert("beta");
        assert!(a >= 1);
        assert_ne!(a, b);
        assert_eq!(t.get(a), Some(&"alpha"));
        assert_eq!(t.get(b), Some(&"beta"));
    }

    #[test]
    fn remove_and_reuse() {
        let mut t: SocketTable<u32> = SocketTable::new();
        let a = t.insert(10);
        t.remove(a).unwrap();
        let b = t.insert(20);
        assert_eq!(a, b, "freed ids should be recycled");
        assert_eq!(t.get(b), Some(&20));
    }

    #[test]
    fn id_zero_is_reserved() {
        let mut t: SocketTable<u32> = SocketTable::new();
        for _ in 0..5 {
            let id = t.insert(0);
            assert_ne!(id, 0);
        }
    }
}
