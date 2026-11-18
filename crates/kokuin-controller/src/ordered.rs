//! Insertion-ordered collections, as JavaScript's `Set` and `Map` iterate. The fold's deny set and
//! member map are read back in that order (`snapshotOf`, a snapshot's `d` and `m`), so the order is
//! part of the answer.

use std::collections::HashMap;

/// A set of strings that iterates in first-insertion order, as a JavaScript `Set<string>`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrderedSet {
    items: Vec<String>,
    index: HashMap<String, usize>,
}

impl OrderedSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `item`, keeping the position of an existing one.
    pub fn insert(&mut self, item: impl Into<String>) {
        let item = item.into();
        if !self.index.contains_key(&item) {
            self.index.insert(item.clone(), self.items.len());
            self.items.push(item);
        }
    }

    /// Whether `item` is in the set.
    pub fn contains(&self, item: &str) -> bool {
        self.index.contains_key(item)
    }

    /// The items, in first-insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.items.iter()
    }

    /// How many items the set holds.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl<S: Into<String>> FromIterator<S> for OrderedSet {
    fn from_iter<I: IntoIterator<Item = S>>(iter: I) -> Self {
        let mut set = Self::new();
        for item in iter {
            set.insert(item);
        }
        set
    }
}

/// A map keyed by strings that iterates in first-insertion order, as a JavaScript `Map<string, V>`:
/// setting an existing key replaces its value in place.
#[derive(Clone, Debug, PartialEq)]
pub struct OrderedMap<V> {
    entries: Vec<(String, V)>,
    index: HashMap<String, usize>,
}

impl<V> Default for OrderedMap<V> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            index: HashMap::new(),
        }
    }
}

impl<V> OrderedMap<V> {
    /// An empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `key` to `value`, keeping the position of an existing key.
    pub fn insert(&mut self, key: impl Into<String>, value: V) {
        let key = key.into();
        match self.index.get(&key) {
            Some(&position) => self.entries[position].1 = value,
            None => {
                self.index.insert(key.clone(), self.entries.len());
                self.entries.push((key, value));
            }
        }
    }

    /// The value at `key`.
    pub fn get(&self, key: &str) -> Option<&V> {
        self.index
            .get(key)
            .map(|&position| &self.entries[position].1)
    }

    /// The value at `key`, mutably.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        self.index
            .get(key)
            .map(|&position| &mut self.entries[position].1)
    }

    /// The entries, in first-insertion order, by value.
    pub fn into_entries(self) -> Vec<(String, V)> {
        self.entries
    }

    /// Whether `key` is present.
    pub fn contains_key(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }

    /// The entries, in first-insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.entries.iter().map(|(key, value)| (key, value))
    }

    /// The values, in first-insertion order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, value)| value)
    }

    /// How many entries the map holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
