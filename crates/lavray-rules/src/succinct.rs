// SPDX-License-Identifier: GPL-3.0-only

//! Succinct set доменов (порт sing/common/domain/set.go, openacid/succinct):
//! чтение из .srs + матching `has(reverse_domain(host))`. Биттрик rank/select
//! повторяют Go-алгоритмы (ranks/selects/labels/leaves).

const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

/// Succinct-множество реверс-доменов.
#[derive(Debug, Clone)]
pub struct SuccinctSet {
    pub(crate) leaves: Vec<u64>,
    pub(crate) label_bitmap: Vec<u64>,
    pub(crate) labels: Vec<u8>,
    pub(crate) ranks: Vec<usize>,
    pub(crate) selects: Vec<usize>,
}

impl SuccinctSet {
    /// Собрать из сырых компонент (формат .srs: leaves, labelBitmap, labels).
    ///
    /// # Errors
    /// `domain: malformed succinct set` — нарушенные инварианты (паритет Go).
    pub fn from_parts(
        mut leaves: Vec<u64>,
        label_bitmap: Vec<u64>,
        labels: Vec<u8>,
    ) -> Result<Self, String> {
        let mut ones_count: usize = 0;
        let mut last_one_index: Option<usize> = None;
        for (wi, &word) in label_bitmap.iter().enumerate() {
            ones_count += word.count_ones() as usize;
            if word != 0 {
                let high = (wi << 6) | word.ilog2() as usize;
                last_one_index = Some(high);
            }
        }
        let zeros_count = last_one_index.map_or(0, |i| i + 1 - ones_count);
        if label_bitmap.is_empty() {
            return Ok(Self {
                leaves,
                label_bitmap,
                labels,
                ranks: Vec::new(),
                selects: Vec::new(),
            });
        }
        if ones_count != zeros_count + 1 || labels.len() != zeros_count {
            return Err("domain: malformed succinct set".into());
        }
        let need = ones_count.div_ceil(64);
        if leaves.len() < need {
            leaves.resize(need, 0);
        }
        let mut set = Self {
            leaves,
            label_bitmap,
            labels,
            ranks: Vec::new(),
            selects: Vec::new(),
        };
        set.init();
        Ok(set)
    }

    pub(crate) fn init(&mut self) {
        self.selects = crate::succinct_idx::build_selects(&self.label_bitmap);
        self.ranks = crate::succinct_idx::build_ranks(&self.label_bitmap);
    }

    pub(crate) fn get_bit(bm: &[u64], i: usize) -> bool {
        bm[i >> 6] & (1_u64 << (i & 63)) != 0
    }

    pub(crate) fn count_zeros(&self, i: usize) -> usize {
        i - self.rank(i)
    }

    /// Кол-во единиц в первых i битах (rank64: сумма слов до wordI + хвост).
    pub(crate) fn rank(&self, i: usize) -> usize {
        let word_i = i >> 6;
        let j = i & 63;
        // ranks с trailing-словом: word_i ≤ len(label_bitmap)
        let mut ones = self.ranks[word_i];
        if word_i < self.label_bitmap.len() {
            let w = self.label_bitmap[word_i];
            let mask = if j == 0 { 0 } else { (1_u64 << j) - 1 };
            ones += (w & mask).count_ones() as usize;
        }
        ones
    }

    /// Позиция i-й единицы (порт select32R64: спуск 32/16/8 + select8).
    // Сужения u64→u32/u16/u8 — сама суть побитового спуска (порт Go).
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn select_ith_one(&self, i: usize) -> usize {
        // Стартовое слово — из selects-индекса (каждая 32-я единица).
        let mut word_i = self.selects[i >> 5] >> 6;
        while word_i + 1 < self.ranks.len() && self.ranks[word_i + 1] <= i {
            word_i += 1;
        }
        let base = word_i << 6;
        let w = self.label_bitmap[word_i];
        let mut ww = w;
        let mut offset: u32 = 0;
        let mut find_ith = i - self.ranks[word_i];
        let ones = (ww as u32).count_ones() as usize;
        if ones <= find_ith {
            find_ith -= ones;
            offset |= 32;
            ww >>= 32;
        }
        let ones = (ww as u16).count_ones() as usize;
        if ones <= find_ith {
            find_ith -= ones;
            offset |= 16;
            ww >>= 16;
        }
        let ones = (ww as u8).count_ones() as usize;
        let byte = (ww & 0xff) as u8;
        let pos_in_byte = if ones <= find_ith {
            // единица — в старших 8 битах младших 16
            let hi = (ww >> 8) as u8;
            crate::succinct_idx::select8(hi, find_ith - ones) + 8
        } else {
            crate::succinct_idx::select8(byte, find_ith)
        };
        base + pos_in_byte as usize + offset as usize
    }

    /// Матчинг по реверс-ключу (has() Go). Пустое множество — всегда false.
    pub fn has(&self, key: &[u8]) -> bool {
        if self.label_bitmap.is_empty() {
            return false;
        }
        let mut node_id: usize = 0;
        let mut bm_idx: usize = 0;
        for &current_char in key {
            loop {
                if Self::get_bit(&self.label_bitmap, bm_idx) {
                    return false;
                }
                let next_label = self.labels[bm_idx - node_id];
                if next_label == PREFIX_LABEL {
                    return true;
                }
                if next_label == ROOT_LABEL {
                    let next_node_id = self.count_zeros(bm_idx + 1);
                    let has_next = Self::get_bit(&self.leaves, next_node_id);
                    if current_char == b'.' && has_next {
                        return true;
                    }
                }
                if next_label == current_char {
                    break;
                }
                bm_idx += 1;
            }
            node_id = self.count_zeros(bm_idx + 1);
            bm_idx = self.select_ith_one(node_id - 1) + 1;
        }
        if Self::get_bit(&self.leaves, node_id) {
            return true;
        }
        loop {
            if Self::get_bit(&self.label_bitmap, bm_idx) {
                return false;
            }
            let next_label = self.labels[bm_idx - node_id];
            if next_label == PREFIX_LABEL || next_label == ROOT_LABEL {
                return true;
            }
            bm_idx += 1;
        }
    }
}
