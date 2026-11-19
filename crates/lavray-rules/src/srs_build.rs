// SPDX-License-Identifier: GPL-3.0-only

//! Построение succinct set по отсортированным реверс-ключам
//! (порт newSuccinctSet: BFS по общим префиксам).

/// (leaves, labelBitmap, labels) — как Go newSuccinctSet.
pub(crate) fn build_succinct(keys: &[Vec<u8>]) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
    if keys.is_empty() {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    let mut leaves: Vec<u64> = Vec::new();
    let mut label_bitmap: Vec<u64> = Vec::new();
    let mut labels: Vec<u8> = Vec::new();
    let mut l_idx = 0usize;
    let mut queue: Vec<(usize, usize, usize)> = vec![(0, keys.len(), 0)];
    let mut i = 0usize;
    while i < queue.len() {
        let (mut s, e, col) = queue[i];
        if keys[s].len() == col {
            // лист
            s += 1;
            set_bit(&mut leaves, i, 1);
        }
        let mut j = s;
        while j < e {
            let frm = j;
            while j < e && keys[j][col] == keys[frm][col] {
                j += 1;
            }
            queue.push((frm, j, col + 1));
            labels.push(keys[frm][col]);
            set_bit(&mut label_bitmap, l_idx, 0);
            l_idx += 1;
        }
        set_bit(&mut label_bitmap, l_idx, 1);
        l_idx += 1;
        i += 1;
    }
    (leaves, label_bitmap, labels)
}

fn set_bit(bm: &mut Vec<u64>, i: usize, v: u64) {
    while i >> 6 >= bm.len() {
        bm.push(0);
    }
    bm[i >> 6] |= v << (i & 63);
}
