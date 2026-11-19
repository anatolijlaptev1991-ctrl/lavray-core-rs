// SPDX-License-Identifier: GPL-3.0-only

//! Индексы succinct set (порт indexSelect32R64/indexRank64): selects —
//! позиция каждой 32-й единицы, ranks — префикс-суммы popcount (+trailing).

/// Позиции каждой 32-й единицы bitmap (selects).
#[must_use]
pub(crate) fn build_selects(label_bitmap: &[u64]) -> Vec<usize> {
    let total_bits = label_bitmap.len() << 6;
    let mut sidx = Vec::new();
    let mut ones_seen: usize = 0;
    for i in 0..total_bits {
        if label_bitmap[i >> 6] & (1_u64 << (i & 63)) != 0 {
            // позиция каждой 32-й единицы (k-я, k % 32 == 1)
            if ones_seen.trailing_zeros() >= 5 {
                sidx.push(i);
            }
            ones_seen += 1;
        }
    }
    sidx
}

/// Префикс-суммы popcount по словам (+1 trailing-слово).
#[must_use]
pub(crate) fn build_ranks(label_bitmap: &[u64]) -> Vec<usize> {
    let mut idx = Vec::with_capacity(label_bitmap.len() + 1);
    let mut n: usize = 0;
    for &w in label_bitmap {
        idx.push(n);
        n += w.count_ones() as usize;
    }
    idx.push(n);
    idx
}

/// Позиция k-й единицы в байте (порт select8Lookup; 8 = не найдена).
pub(crate) fn select8(byte: u8, k: usize) -> u32 {
    let mut w = byte;
    for _ in 0..k {
        w &= w - 1;
    }
    if w == 0 { 8 } else { w.trailing_zeros() }
}
