use crate::error::StoreError;
use crate::file::{TableFile, FILE_HEADER_LEN};
use crate::hashhead::{initial_slots_for, HashHead, HeadScale};
use bitcoin::block::{Header, HeaderV2, Version};
use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
use bitcoin_hashes::{sha256, Hash, HashEngine};
use rbitcoin_primitives::{Fk, TableKind};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

pub const HEADER_HEAD_DIR_REFUSE: &str =
    "header.head is a shard directory; wipe header.head and header.body and reindex";

pub const HEADER_HEAD_EMPTY_REFUSE: &str =
    "header.head is empty at target slots; wipe header.head, header.head.mlt, and header.body and reindex";

/// Live `header.body` record: consensus fields plus the Knots v2 extension
/// (zeros for a classic header). See SCHEMA.md.
pub const HEADER_RECORD_LEN: usize = HEADER_RECORD_LEN_V26 + HeaderV2::SIZE; // 172
/// Schema 26 record: the 88 consensus bytes only. Open widens to 172.
pub const HEADER_RECORD_LEN_V26: usize = 88;
/// Schema 24/25 record. Open strips the trailing `size`/`weight` back to 88.
pub const HEADER_RECORD_LEN_V24: usize = 96;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HeaderRecord {
    pub prev_fk: Fk,
    /// Base version: the wire version without [`Header::V2_VERSION_FLAG`], which the
    /// row's `version` column carries when `v2` is present.
    pub version: i32,
    /// Consensus time (a v2 header's wire time plus its offset).
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
    pub merkle_root: [u8; 32],
    pub hash: [u8; 32],
    /// Knots v2 extension, `None` for a classic 80-byte header.
    pub v2: Option<HeaderV2>,
    /// Not written to `header.body`. Block size comes from `txstat`.
    pub size: u32,
    /// Not written to `header.body`. Block weight comes from `txstat`.
    pub weight: u32,
}

impl HeaderRecord {
    pub fn encode(&self) -> [u8; HEADER_RECORD_LEN] {
        let mut out = [0u8; HEADER_RECORD_LEN];
        out[0..8].copy_from_slice(&self.prev_fk.0.to_le_bytes());
        let wire_version = match self.v2 {
            Some(_) => self.version as u32 | Header::V2_VERSION_FLAG,
            None => self.version as u32,
        };
        out[8..12].copy_from_slice(&wire_version.to_le_bytes());
        out[12..16].copy_from_slice(&self.timestamp.to_le_bytes());
        out[16..20].copy_from_slice(&self.bits.to_le_bytes());
        out[20..24].copy_from_slice(&self.nonce.to_le_bytes());
        out[24..56].copy_from_slice(&self.merkle_root);
        out[56..88].copy_from_slice(&self.hash);
        if let Some(v2) = &self.v2 {
            let tail = &mut out[88..172];
            tail[0..4].copy_from_slice(&v2.nonce2.to_le_bytes());
            tail[4..8].copy_from_slice(&v2.nonce3.to_le_bytes());
            tail[8..24].copy_from_slice(&v2.extranonce);
            tail[24..28].copy_from_slice(&v2.time_offset.to_le_bytes());
            tail[28..30].copy_from_slice(&v2.tx_count.to_le_bytes());
            tail[30] = v2.flags;
            tail[31] = v2.xor_key_mask_clear_bits;
            tail[32..48].copy_from_slice(&v2.xor_key);
            tail[48..52].copy_from_slice(&v2.height.to_le_bytes());
            tail[52..84].copy_from_slice(&v2.mm_rhs);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, StoreError> {
        if buf.len() < HEADER_RECORD_LEN {
            return Err(StoreError::Corrupt("short header record"));
        }
        let wire_version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let v2 = if wire_version & Header::V2_VERSION_FLAG != 0 {
            let tail = &buf[88..172];
            Some(HeaderV2 {
                nonce2: u32::from_le_bytes(tail[0..4].try_into().unwrap()),
                nonce3: u32::from_le_bytes(tail[4..8].try_into().unwrap()),
                extranonce: tail[8..24].try_into().unwrap(),
                time_offset: u32::from_le_bytes(tail[24..28].try_into().unwrap()),
                tx_count: u16::from_le_bytes(tail[28..30].try_into().unwrap()),
                flags: tail[30],
                xor_key_mask_clear_bits: tail[31],
                xor_key: tail[32..48].try_into().unwrap(),
                height: i32::from_le_bytes(tail[48..52].try_into().unwrap()),
                mm_rhs: tail[52..84].try_into().unwrap(),
            })
        } else {
            None
        };
        Ok(Self {
            prev_fk: Fk(u64::from_le_bytes(buf[0..8].try_into().unwrap())),
            version: (wire_version & !Header::V2_VERSION_FLAG) as i32,
            timestamp: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            bits: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            nonce: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            merkle_root: buf[24..56].try_into().unwrap(),
            hash: buf[56..88].try_into().unwrap(),
            v2,
            size: 0,
            weight: 0,
        })
    }

    /// The wire header this row stores, given the parent's hash.
    pub fn wire_header(&self, prev_hash: &[u8; 32]) -> Header {
        Header {
            version: Version::from_consensus(self.version),
            prev_blockhash: BlockHash::from_byte_array(*prev_hash),
            merkle_root: TxMerkleNode::from_byte_array(self.merkle_root),
            time: self.timestamp,
            bits: CompactTarget::from_consensus(self.bits),
            nonce: self.nonce,
            v2: self.v2,
        }
    }

    /// Serialized header length: 80, or 164 with the v2 extension.
    pub fn header_size(&self) -> u64 {
        match self.v2 {
            Some(_) => Header::V2_SIZE as u64,
            None => Header::SIZE as u64,
        }
    }

    /// Block hash of the header this row stores, internal byte order.
    pub fn block_hash(&self, prev_hash: &[u8; 32]) -> [u8; 32] {
        self.wire_header(prev_hash).block_hash().to_byte_array()
    }
}

/// Double-SHA256 of a bitcoin block header (80 bytes), internal byte order.
pub fn block_header_hash(
    version: i32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    timestamp: u32,
    bits: u32,
    nonce: u32,
) -> [u8; 32] {
    let mut ser = [0u8; 80];
    ser[0..4].copy_from_slice(&version.to_le_bytes());
    ser[4..36].copy_from_slice(prev_hash);
    ser[36..68].copy_from_slice(merkle_root);
    ser[68..72].copy_from_slice(&timestamp.to_le_bytes());
    ser[72..76].copy_from_slice(&bits.to_le_bytes());
    ser[76..80].copy_from_slice(&nonce.to_le_bytes());
    let mut eng = sha256::HashEngine::default();
    eng.input(&ser);
    let mid = sha256::Hash::from_engine(eng);
    let mut eng2 = sha256::HashEngine::default();
    eng2.input(mid.as_byte_array());
    sha256::Hash::from_engine(eng2).to_byte_array()
}

/// `header.head` plus overflow gens `header.head.g1`, `header.head.g2`, …
struct HeaderHead {
    base: PathBuf,
    target_slots: u64,
    gens: RwLock<Vec<HashHead>>,
}

fn header_head_occupied(dir: &Path) -> Result<u64, StoreError> {
    let base = dir.join("header.head");
    if !base.is_file() {
        return Ok(0);
    }
    let mut n = HashHead::open(&base)?.occupied();
    let mut i = 1usize;
    loop {
        let p = header_gen_path(&base, i);
        if !p.is_file() {
            break;
        }
        n = n.saturating_add(HashHead::open(p)?.occupied());
        i += 1;
    }
    Ok(n)
}

fn header_gen_path(base: &Path, i: usize) -> PathBuf {
    if i == 0 {
        return base.to_path_buf();
    }
    let mut p = base.as_os_str().to_os_string();
    p.push(format!(".g{i}"));
    PathBuf::from(p)
}

impl HeaderHead {
    fn create(base: PathBuf, scale: HeadScale) -> Result<Self, StoreError> {
        let target_slots = initial_slots_for(scale);
        let h = HashHead::create_with_slots(&base, target_slots)?;
        Ok(Self {
            base,
            target_slots,
            gens: RwLock::new(vec![h]),
        })
    }

    fn open(base: PathBuf, body_count: u64, scale: HeadScale) -> Result<Self, StoreError> {
        if base.is_dir() {
            return Err(StoreError::Layout(HEADER_HEAD_DIR_REFUSE.to_string()));
        }
        if !base.is_file() {
            return Err(StoreError::io(
                &base,
                std::io::Error::new(std::io::ErrorKind::NotFound, "header.head missing"),
            ));
        }
        crate::hashhead::discard_grow_part(&base);
        let target_slots = initial_slots_for(scale);
        let mut gens = vec![HashHead::open(&base)?];
        let mut i = 1usize;
        loop {
            let p = header_gen_path(&base, i);
            if !p.is_file() {
                break;
            }
            gens.push(HashHead::open(p)?);
            i += 1;
        }
        if gens.len() == 1 && gens[0].slots() < target_slots {
            let g = gens.remove(0);
            gens.push(g.rewrite_to_slots(target_slots)?);
        } else if gens.len() == 1
            && gens[0].slots() >= target_slots
            && gens[0].occupied() == 0
            && (body_count > 0 || gens[0].multi_count() > 0)
        {
            return Err(StoreError::Layout(HEADER_HEAD_EMPTY_REFUSE.to_string()));
        }
        Ok(Self {
            base,
            target_slots,
            gens: RwLock::new(gens),
        })
    }

    fn get_all(&self, key: &[u8; 32]) -> Result<Vec<Fk>, StoreError> {
        let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for h in gens.iter().rev() {
            out.extend(h.get_all(key)?);
        }
        Ok(out)
    }

    fn insert_many(&self, entries: &[([u8; 32], Fk)]) -> Result<(), StoreError> {
        let mut rest: Vec<([u8; 32], Fk)> = entries.to_vec();
        while !rest.is_empty() {
            let leftover = {
                let last = {
                    let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
                    gens.len().saturating_sub(1)
                };
                let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
                gens[last].insert_many_file(&rest, |_| {})?
            };
            if leftover.is_empty() {
                return Ok(());
            }
            self.roll()?;
            rest = leftover;
        }
        Ok(())
    }

    fn roll(&self) -> Result<(), StoreError> {
        let mut gens = self.gens.write().unwrap_or_else(|e| e.into_inner());
        // Another ensure may have rolled while we dropped the read lock.
        if gens.last().is_some_and(|h| !h.at_load_cap()) {
            return Ok(());
        }
        let i = gens.len();
        let p = header_gen_path(&self.base, i);
        gens.push(HashHead::create_with_slots(p, self.target_slots)?);
        Ok(())
    }

    fn flush(&self) -> Result<(), StoreError> {
        let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
        for h in gens.iter() {
            h.flush()?;
        }
        Ok(())
    }

    fn flush_async(&self) -> Result<(), StoreError> {
        let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
        for h in gens.iter() {
            h.flush_async()?;
        }
        Ok(())
    }
}

pub struct HeaderTable {
    body: TableFile,
    head: HeaderHead,
    count: std::sync::atomic::AtomicU64,
    /// Serializes check-then-put so two threads cannot both miss and both append
    /// the same full hash (I1 + I4).
    put_lock: Mutex<()>,
}

impl HeaderTable {
    pub fn create(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::create_with_scale(dir, HeadScale::Mainnet)
    }

    pub fn create_tiny(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::create_with_scale(dir, HeadScale::Tiny)
    }

    pub fn create_with_scale(dir: &std::path::Path, scale: HeadScale) -> Result<Self, StoreError> {
        let body = TableFile::create(dir.join("header.body"), TableKind::Header)?;
        let head = HeaderHead::create(dir.join("header.head"), scale)?;
        Ok(Self {
            body,
            head,
            count: std::sync::atomic::AtomicU64::new(0),
            put_lock: Mutex::new(()),
        })
    }

    pub fn open(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::open_with_scale(dir, HeadScale::Mainnet)
    }

    pub fn open_tiny(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::open_with_scale(dir, HeadScale::Tiny)
    }

    pub fn open_with_scale(dir: &std::path::Path, scale: HeadScale) -> Result<Self, StoreError> {
        let body = TableFile::open(dir.join("header.body"), TableKind::Header)?;
        let body_len = body.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if body_len % HEADER_RECORD_LEN as u64 != 0 {
            return Err(StoreError::Corrupt("header body size"));
        }
        let count = body_len / HEADER_RECORD_LEN as u64;
        let head = HeaderHead::open(dir.join("header.head"), count, scale)?;
        Ok(Self {
            body,
            head,
            count: std::sync::atomic::AtomicU64::new(count),
            put_lock: Mutex::new(()),
        })
    }

    /// Schema 24/25 → 26: strip trailing `size`/`weight` so each row is 88 B.
    ///
    /// Writes `header.body.grow`, fsyncs, renames over `header.body`. A body
    /// that is already 88 B is left alone. Occupied `header.head` disambiguates
    /// lengths that divide both 88 and 96.
    pub(crate) fn rewrite_v24_body_to_88(dir: &Path) -> Result<(), StoreError> {
        let path = dir.join("header.body");
        if !path.is_file() {
            return Ok(());
        }
        let grow = {
            let mut p = path.as_os_str().to_os_string();
            p.push(".grow");
            PathBuf::from(p)
        };
        let _ = std::fs::remove_file(&grow);
        let src = TableFile::open(&path, TableKind::Header)?;
        let body_len = src.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if body_len == 0 {
            return Ok(());
        }
        if body_len % HEADER_RECORD_LEN as u64 == 0 {
            let occ = header_head_occupied(dir)?;
            if occ == body_len / HEADER_RECORD_LEN as u64 || occ == 0 {
                return Ok(());
            }
        }
        let n88 = body_len / HEADER_RECORD_LEN_V26 as u64;
        let n96 = body_len / HEADER_RECORD_LEN_V24 as u64;
        let aligned88 = body_len % HEADER_RECORD_LEN_V26 as u64 == 0;
        let aligned96 = body_len % HEADER_RECORD_LEN_V24 as u64 == 0;
        let n = if aligned96 && aligned88 {
            let occ = header_head_occupied(dir)?;
            if occ == n88 || occ == 0 {
                return Ok(());
            }
            if occ == n96 {
                n96
            } else {
                return Err(StoreError::Corrupt("header body size"));
            }
        } else if aligned88 {
            return Ok(());
        } else if aligned96 {
            n96
        } else {
            return Err(StoreError::Corrupt("header body size"));
        };
        let dst = TableFile::create(&grow, TableKind::Header)?;
        let mut blob = Vec::new();
        blob.try_reserve_exact(n as usize * HEADER_RECORD_LEN_V26)
            .map_err(|_| StoreError::Corrupt("header body rewrite OOM"))?;
        for i in 0..n {
            let off = FILE_HEADER_LEN as u64 + i * HEADER_RECORD_LEN_V24 as u64;
            let mut raw = [0u8; HEADER_RECORD_LEN_V24];
            src.read_at(off, &mut raw)?;
            blob.extend_from_slice(&raw[..HEADER_RECORD_LEN_V26]);
        }
        let new_len = FILE_HEADER_LEN as u64 + n * HEADER_RECORD_LEN_V26 as u64;
        dst.write_at(FILE_HEADER_LEN as u64, &blob)?;
        dst.set_logical_len(new_len)?;
        dst.flush()?;
        drop(dst);
        drop(src);
        std::fs::rename(&grow, &path).map_err(|e| StoreError::io(&path, e))?;
        Ok(())
    }

    /// Schema 26 → 27: widen each 88 B row to 172 B (zero v2 tail).
    ///
    /// Same shape as [`Self::rewrite_v24_body_to_88`]: `header.body.grow`,
    /// fsync, rename. A body that is already 172 B is left alone. Occupied
    /// `header.head` disambiguates lengths that divide both 88 and 172.
    pub(crate) fn rewrite_v26_body_to_172(dir: &Path) -> Result<(), StoreError> {
        let path = dir.join("header.body");
        if !path.is_file() {
            return Ok(());
        }
        let grow = {
            let mut p = path.as_os_str().to_os_string();
            p.push(".grow");
            PathBuf::from(p)
        };
        let _ = std::fs::remove_file(&grow);
        let src = TableFile::open(&path, TableKind::Header)?;
        let body_len = src.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if body_len == 0 {
            return Ok(());
        }
        let n88 = body_len / HEADER_RECORD_LEN_V26 as u64;
        let n172 = body_len / HEADER_RECORD_LEN as u64;
        let aligned88 = body_len % HEADER_RECORD_LEN_V26 as u64 == 0;
        let aligned172 = body_len % HEADER_RECORD_LEN as u64 == 0;
        let n = if aligned172 && aligned88 {
            let occ = header_head_occupied(dir)?;
            if occ == n172 || occ == 0 {
                return Ok(());
            }
            if occ == n88 {
                n88
            } else {
                return Err(StoreError::Corrupt("header body size"));
            }
        } else if aligned172 {
            return Ok(());
        } else if aligned88 {
            n88
        } else {
            return Err(StoreError::Corrupt("header body size"));
        };
        let dst = TableFile::create(&grow, TableKind::Header)?;
        let mut blob = Vec::new();
        blob.try_reserve_exact(n as usize * HEADER_RECORD_LEN)
            .map_err(|_| StoreError::Corrupt("header body rewrite OOM"))?;
        for i in 0..n {
            let off = FILE_HEADER_LEN as u64 + i * HEADER_RECORD_LEN_V26 as u64;
            let mut raw = [0u8; HEADER_RECORD_LEN];
            src.read_at(off, &mut raw[..HEADER_RECORD_LEN_V26])?;
            blob.extend_from_slice(&raw);
        }
        let new_len = FILE_HEADER_LEN as u64 + n * HEADER_RECORD_LEN as u64;
        dst.write_at(FILE_HEADER_LEN as u64, &blob)?;
        dst.set_logical_len(new_len)?;
        dst.flush()?;
        drop(dst);
        drop(src);
        std::fs::rename(&grow, &path).map_err(|e| StoreError::io(&path, e))?;
        Ok(())
    }

    pub fn head_target_slots(&self) -> u64 {
        self.head.target_slots
    }

    /// Write gate: at most one body row per full block hash (I1).
    ///
    /// - If `hash` already exists → return that fk (ignore caller's `prev_fk`).
    /// - Else if `prev_fk` is non-null → parent must exist and
    ///   `hash` must equal SHA256D(header fields with parent.hash as prev) (I2/I3).
    /// - Else (`prev_fk` null) → append as-is (genesis / synthetic test rows).
    ///
    /// Lookup + insert hold [`Self::put_lock`] (I4).
    pub fn ensure(&self, rec: &HeaderRecord) -> Result<Fk, StoreError> {
        let mut fks = self.ensure_batch(std::slice::from_ref(rec))?;
        fks.pop().ok_or(StoreError::Corrupt("ensure_batch empty"))
    }

    /// Batch [`Self::ensure`]: one `put_lock`, one `header.body` write, chunked head insert.
    ///
    /// Output fks align with `recs`. Duplicate hashes in the batch share one body row.
    pub fn ensure_batch(&self, recs: &[HeaderRecord]) -> Result<Vec<Fk>, StoreError> {
        use std::sync::atomic::Ordering;
        if recs.is_empty() {
            return Ok(Vec::new());
        }
        let _g = self.put_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(recs.len());
        let mut fresh: Vec<(Fk, HeaderRecord)> = Vec::new();
        let mut seen: Vec<([u8; 32], Fk)> = Vec::new();
        let mut next = self.count.load(Ordering::Acquire);
        for rec in recs {
            if let Some((_, fk)) = seen.iter().rev().find(|(h, _)| *h == rec.hash) {
                out.push(*fk);
                continue;
            }
            if let Some((fk, _)) = self.get_by_hash_unlocked(&rec.hash)? {
                seen.push((rec.hash, fk));
                out.push(fk);
                continue;
            }
            if !rec.prev_fk.is_null() {
                let parent = self.parent_for_batch(rec.prev_fk, &fresh)?;
                Self::check_parent_edge(rec, &parent)?;
            }
            next = next.saturating_add(1);
            let fk = Fk(next);
            let mut stored = rec.clone();
            stored.prev_fk = rec.prev_fk;
            fresh.push((fk, stored));
            seen.push((rec.hash, fk));
            out.push(fk);
        }
        if fresh.is_empty() {
            return Ok(out);
        }
        let base = self.count.load(Ordering::Acquire);
        let offset = FILE_HEADER_LEN as u64 + base * HEADER_RECORD_LEN as u64;
        let mut blob = Vec::with_capacity(fresh.len().saturating_mul(HEADER_RECORD_LEN));
        let mut head_entries: Vec<([u8; 32], Fk)> = Vec::with_capacity(fresh.len());
        for (fk, rec) in &fresh {
            blob.extend_from_slice(&rec.encode());
            head_entries.push((rec.hash, *fk));
        }
        self.body.write_at(offset, &blob)?;
        self.count
            .store(base.saturating_add(fresh.len() as u64), Ordering::Release);
        self.head.insert_many(&head_entries)?;
        Ok(out)
    }

    fn parent_for_batch(
        &self,
        prev_fk: Fk,
        fresh: &[(Fk, HeaderRecord)],
    ) -> Result<HeaderRecord, StoreError> {
        if let Some((_, rec)) = fresh.iter().rev().find(|(fk, _)| *fk == prev_fk) {
            return Ok(rec.clone());
        }
        self.get(prev_fk)
    }

    fn check_parent_edge(rec: &HeaderRecord, parent: &HeaderRecord) -> Result<(), StoreError> {
        if rec.block_hash(&parent.hash) != rec.hash {
            return Err(StoreError::Corrupt(
                "header prev_fk does not match block hash (false parent edge)",
            ));
        }
        Ok(())
    }

    pub fn get(&self, fk: Fk) -> Result<HeaderRecord, StoreError> {
        use std::sync::atomic::Ordering;
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        let count = self.count.load(Ordering::Acquire);
        if id == 0 || id > count {
            return Err(StoreError::NotFound);
        }
        let offset = FILE_HEADER_LEN as u64 + (id - 1) * HEADER_RECORD_LEN as u64;
        let mut buf = [0u8; HEADER_RECORD_LEN];
        self.body.read_at(offset, &mut buf)?;
        HeaderRecord::decode(&buf)
    }

    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Result<Option<(Fk, HeaderRecord)>, StoreError> {
        // Head reads are safe without put_lock (body append-only; head multi-list
        // is append-oriented). Callers that check-then-put must use ensure.
        self.get_by_hash_unlocked(hash)
    }

    fn get_by_hash_unlocked(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<(Fk, HeaderRecord)>, StoreError> {
        // 16-byte head prefix may collide — verify full hash on the body.
        for fk in self.head.get_all(hash)? {
            let rec = self.get(fk)?;
            if rec.hash == *hash {
                return Ok(Some((fk, rec)));
            }
        }
        Ok(None)
    }

    /// Number of header rows currently stored (highest fk = this value).
    pub fn count(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        self.body.flush()?;
        self.head.flush()?;
        Ok(())
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.body.flush_async()?;
        self.head.flush_async()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "rbitcoin-header-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn sample(hash: [u8; 32]) -> HeaderRecord {
        HeaderRecord {
            prev_fk: Fk::NULL,
            version: 1,
            timestamp: 100,
            bits: 0x1d00ffff,
            nonce: 7,
            merkle_root: [2u8; 32],
            hash,
            size: 0,
            weight: 0,
            v2: None,
        }
    }

    #[test]
    fn header_put_get_by_hash_open_flush() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let fk1 = t.ensure(&sample(h1)).unwrap();
        let fk2 = t.ensure(&sample(h2)).unwrap();
        assert_eq!(t.count(), 2);
        assert_eq!(t.get(fk1).unwrap().hash, h1);
        assert_eq!(t.get(fk2).unwrap().hash, h2);
        assert_eq!(t.get_by_hash(&h1).unwrap().unwrap().0, fk1);
        assert!(t.get_by_hash(&[9u8; 32]).unwrap().is_none());
        assert!(matches!(t.get(Fk::NULL), Err(StoreError::InvalidFk)));
        assert!(matches!(t.get(Fk(99)), Err(StoreError::NotFound)));
        // short decode
        assert!(matches!(
            HeaderRecord::decode(&[0u8; 10]),
            Err(StoreError::Corrupt(_))
        ));
        t.flush().unwrap();
        t.flush_async().unwrap();
        drop(t);
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(t.count(), 2);
        assert_eq!(t.get_by_hash(&h2).unwrap().unwrap().1.nonce, 7);
        // Shrink OS file below HWM so open clamps logical to a non-record size.
        {
            use crate::file::FILE_HEADER_LEN;
            let body = dir.join("header.body");
            std::fs::OpenOptions::new()
                .write(true)
                .open(&body)
                .unwrap()
                .set_len((FILE_HEADER_LEN + 3) as u64)
                .unwrap();
        }
        assert!(matches!(
            HeaderTable::open_tiny(&dir),
            Err(StoreError::Corrupt(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Real block-header fields with PoW-style hash committed to a real parent.
    fn linked_child(parent: &HeaderRecord, parent_fk: Fk, salt: u32) -> HeaderRecord {
        let version = 1;
        let timestamp = 1_700_000_000 + salt;
        let bits = 0x207fffff;
        let nonce = salt;
        let mut merkle = [0u8; 32];
        merkle[0..4].copy_from_slice(&salt.to_le_bytes());
        let hash = block_header_hash(version, &parent.hash, &merkle, timestamp, bits, nonce);
        HeaderRecord {
            prev_fk: parent_fk,
            version,
            timestamp,
            bits,
            nonce,
            merkle_root: merkle,
            hash,
            size: 0,
            weight: 0,
            v2: None,
        }
    }

    #[test]
    fn ensure_batch_linked_headers_roundtrip() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let g = sample([0x10; 32]);
        let a = linked_child(&g, Fk(1), 1);
        let b = linked_child(&a, Fk(2), 2);
        let fks = t.ensure_batch(&[g.clone(), a.clone(), b.clone()]).unwrap();
        assert_eq!(fks, vec![Fk(1), Fk(2), Fk(3)]);
        assert_eq!(t.count(), 3);
        assert_eq!(t.get_by_hash(&g.hash).unwrap().unwrap().0, Fk(1));
        assert_eq!(t.get_by_hash(&b.hash).unwrap().unwrap().0, Fk(3));
        drop(t);
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(t.count(), 3);
        assert_eq!(t.get_by_hash(&a.hash).unwrap().unwrap().1.nonce, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_batch_duplicate_hash_is_one_row() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let g = sample([0x21; 32]);
        let fks = t.ensure_batch(&[g.clone(), g.clone()]).unwrap();
        assert_eq!(fks[0], fks[1]);
        assert_eq!(t.count(), 1);
        let again = t.ensure_batch(&[g]).unwrap();
        assert_eq!(again[0], fks[0]);
        assert_eq!(t.count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_batch_false_parent_writes_nothing() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let g = sample([0x31; 32]);
        let a = linked_child(&g, Fk(1), 1);
        let honest = linked_child(&a, Fk(2), 2);
        let mut lying = honest.clone();
        lying.prev_fk = Fk(1);
        let err = t.ensure_batch(&[g.clone(), a.clone(), lying]).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt(_)),
            "false parent edge must be rejected, got {err}"
        );
        assert_eq!(t.count(), 0, "failed batch must not append");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_batch_parent_in_batch_assigns_prev_fk() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let g = sample([0x41; 32]);
        let a = linked_child(&g, Fk(1), 7);
        let fks = t.ensure_batch(&[g, a.clone()]).unwrap();
        assert_eq!(fks, vec![Fk(1), Fk(2)]);
        assert_eq!(t.get(Fk(2)).unwrap().prev_fk, Fk(1));
        assert_eq!(t.get(Fk(2)).unwrap().hash, a.hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Production failure shape: same full hash as an older block, but `prev_fk`
    /// points at a tip-extension header. Without the write gate this plants a
    /// false child edge that resume walks as "headers past tip".
    #[test]
    fn ensure_rejects_duplicate_hash_with_divergent_prev_and_false_parent_edge() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();

        // G (null prev, synthetic hash) → A → B → C (real linked hashes).
        let g = sample([0x11; 32]);
        let g_fk = t.ensure(&g).unwrap();
        let a = linked_child(&g, g_fk, 1);
        let a_fk = t.ensure(&a).unwrap();
        let b = linked_child(&a, a_fk, 2);
        let b_fk = t.ensure(&b).unwrap();
        let c = linked_child(&b, b_fk, 3);
        let c_fk = t.ensure(&c).unwrap();
        assert_eq!(t.count(), 4);

        // Poison: re-insert G's identity with prev_fk = C (false parent).
        let mut poison = g.clone();
        poison.prev_fk = c_fk;
        // Same hash as G; gate must return G's fk and not append.
        let again = t.ensure(&poison).unwrap();
        assert_eq!(again, g_fk, "same hash must not create a second row");
        assert_eq!(t.count(), 4, "duplicate hash must not grow the table");
        assert_eq!(t.get(g_fk).unwrap().prev_fk, Fk::NULL);

        // First-time insert of a header whose hash commits to A as parent, but
        // caller lies with prev_fk = C → corrupt (false parent edge).
        let honest = linked_child(&a, a_fk, 99);
        let mut lying = honest.clone();
        lying.prev_fk = c_fk;
        let err = t.ensure(&lying).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt(_)),
            "false parent edge must be rejected at write gate, got {err}"
        );
        assert_eq!(t.count(), 4);

        // Honest insert still works.
        let ok = t.ensure(&honest).unwrap();
        assert_eq!(t.count(), 5);
        assert_eq!(t.get(ok).unwrap().prev_fk, a_fk);

        // Children of C: only what truly points at C (none of the poisons).
        let mut kids_of_c = 0u32;
        for id in 1..=t.count() {
            let rec = t.get(Fk(id)).unwrap();
            if rec.prev_fk == c_fk {
                kids_of_c += 1;
            }
        }
        assert_eq!(
            kids_of_c, 0,
            "C must not gain false children from poison puts"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_head_rolls_generation_when_gen0_is_full() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let mut hashes = Vec::new();
        for i in 0u32..80 {
            let mut hash = [0u8; 32];
            hash[0..4].copy_from_slice(&i.to_le_bytes());
            hash[4] = 0xa5;
            hashes.push(hash);
            t.ensure(&sample(hash)).unwrap();
        }
        assert!(
            dir.join("header.head.g1").is_file(),
            "tiny 64-slot gen0 must roll header.head.g1"
        );
        assert!(dir.join("header.head").is_file());
        let first = t.get_by_hash(&hashes[0]).unwrap().unwrap();
        let last = t.get_by_hash(&hashes[79]).unwrap().unwrap();
        assert_eq!(first.1.hash, hashes[0]);
        assert_eq!(last.1.hash, hashes[79]);
        assert_eq!(t.ensure(&sample(hashes[0])).unwrap(), first.0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_batch_rolls_generation_when_gen0_is_full() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let recs: Vec<HeaderRecord> = (0u32..80)
            .map(|i| {
                let mut hash = [0u8; 32];
                hash[0..4].copy_from_slice(&i.to_le_bytes());
                hash[4] = 0xa5;
                sample(hash)
            })
            .collect();
        let fks = t.ensure_batch(&recs).unwrap();
        assert_eq!(fks.len(), 80);
        assert_eq!(t.count(), 80);
        assert!(
            dir.join("header.head.g1").is_file(),
            "tiny 64-slot gen0 must roll header.head.g1"
        );
        assert_eq!(t.get_by_hash(&recs[0].hash).unwrap().unwrap().0, Fk(1));
        assert_eq!(t.get_by_hash(&recs[79].hash).unwrap().unwrap().0, Fk(80));
        drop(t);
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(
            t.get_by_hash(&recs[40].hash).unwrap().unwrap().1.hash,
            recs[40].hash
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_head_open_grows_undersized_single_gen() {
        let dir = tmp();
        let hashes: Vec<[u8; 32]> = (0u32..5)
            .map(|i| {
                let mut h = [0u8; 32];
                h[0..4].copy_from_slice(&i.to_le_bytes());
                h[8] = 0x3c;
                h
            })
            .collect();
        {
            let body = TableFile::create(dir.join("header.body"), TableKind::Header).unwrap();
            for (i, hash) in hashes.iter().enumerate() {
                let rec = sample(*hash);
                let off = FILE_HEADER_LEN as u64 + (i as u64) * HEADER_RECORD_LEN as u64;
                body.write_at(off, &rec.encode()).unwrap();
            }
            body.set_logical_len(FILE_HEADER_LEN as u64 + 5 * HEADER_RECORD_LEN as u64)
                .unwrap();
            body.flush().unwrap();
            let h = HashHead::create_with_slots(dir.join("header.head"), 32).unwrap();
            for (i, hash) in hashes.iter().enumerate() {
                h.insert(hash, Fk(i as u64 + 1)).unwrap();
            }
            h.flush().unwrap();
            assert_eq!(h.slots(), 32);
        }
        #[cfg(unix)]
        let old = std::fs::File::open(dir.join("header.head")).unwrap();
        #[cfg(unix)]
        let old_ino = {
            use std::os::unix::fs::MetadataExt;
            old.metadata().unwrap().ino()
        };
        let t = HeaderTable::open_tiny(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_ne!(
                std::fs::metadata(dir.join("header.head")).unwrap().ino(),
                old_ino,
                "HeaderTable::open must replace undersized header.head, not punch it"
            );
            drop(old);
        }
        for hash in &hashes {
            assert_eq!(t.get_by_hash(hash).unwrap().unwrap().1.hash, *hash);
        }
        for i in 5u32..40 {
            let mut hash = [0u8; 32];
            hash[0..4].copy_from_slice(&i.to_le_bytes());
            hash[8] = 0x3c;
            t.ensure(&sample(hash)).unwrap();
        }
        assert!(
            !dir.join("header.head.g1").is_file(),
            "open-grow to 64 slots must absorb 40 headers without rolling"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_head_empty_target_sized_gen0_with_body_is_layout_refuse() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        t.ensure(&sample([0x44; 32])).unwrap();
        t.flush().unwrap();
        drop(t);
        std::fs::remove_file(dir.join("header.head")).unwrap();
        let slots = initial_slots_for(HeadScale::Tiny);
        let staging = tmp();
        let h = HashHead::create_with_slots(staging.join("header.head"), slots).unwrap();
        h.flush().unwrap();
        drop(h);
        std::fs::rename(staging.join("header.head"), dir.join("header.head")).unwrap();
        let _ = std::fs::remove_dir_all(&staging);
        let err = match HeaderTable::open_tiny(&dir) {
            Err(e) => e,
            Ok(_) => panic!("expected Layout refuse for empty target-sized header.head"),
        };
        match err {
            StoreError::Layout(m) => {
                assert!(m.contains("header.head"), "{m}");
                assert!(m.contains("header.body"), "{m}");
                assert!(m.contains("header.head.mlt"), "{m}");
            }
            other => panic!("expected Layout, got {other}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_head_directory_is_layout_refuse() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        drop(t);
        let head = dir.join("header.head");
        std::fs::remove_file(&head).unwrap();
        std::fs::create_dir(&head).unwrap();
        std::fs::write(head.join("00"), b"x").unwrap();
        std::fs::write(head.join("01"), b"y").unwrap();
        let err = match HeaderTable::open_tiny(&dir) {
            Err(e) => e,
            Ok(_) => panic!("expected Layout refuse for sharded header.head dir"),
        };
        match err {
            StoreError::Layout(m) => {
                assert!(m.contains("header.head"), "{m}");
            }
            other => panic!("expected Layout, got {other}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_same_hash_twice_is_idempotent() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let h = sample([7u8; 32]);
        let fk1 = t.ensure(&h).unwrap();
        let mut h2 = h.clone();
        h2.prev_fk = Fk(999); // divergent prev ignored on hit
        let fk2 = t.ensure(&h2).unwrap();
        assert_eq!(fk1, fk2);
        assert_eq!(t.count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_record_roundtrip_is_172_bytes() {
        let rec = HeaderRecord {
            size: 285,
            weight: 1140,
            ..sample([1u8; 32])
        };
        let enc = rec.encode();
        assert_eq!(enc.len(), HEADER_RECORD_LEN);
        assert_eq!(HEADER_RECORD_LEN, 172);
        assert!(
            enc[88..].iter().all(|b| *b == 0),
            "classic row has a zero tail"
        );
        assert_eq!(
            &enc[8..12],
            &1u32.to_le_bytes(),
            "no v2 flag on a classic row"
        );
        let back = HeaderRecord::decode(&enc).unwrap();
        assert_eq!(back.size, 0);
        assert_eq!(back.weight, 0);
        assert_eq!(back.hash, rec.hash);
        assert_eq!(back.v2, None);
        assert_eq!(back.header_size(), 80);
        assert!(HeaderRecord::decode(&[0u8; 40]).is_err());
        assert!(HeaderRecord::decode(&[0u8; HEADER_RECORD_LEN_V26]).is_err());
    }

    /// Bitcoin Knots `block_header_v2.json`, vector `profile_0_time_offset`.
    const KNOTS_V2_HEADER_HEX: &str = "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa998877665544332211005802000003001c000000000000000000000000000000000040d10c008967452301efcdab8967452301efcdab8967452301efcdab8967452301efcdab";
    const KNOTS_V2_BLOCK_HASH: &str =
        "4b495dcf05d70a49785b799b22284fbcd9dd1209237c53c87e4674b15587d704";

    fn knots_v2_header() -> Header {
        let raw = rbitcoin_primitives::hex_decode(KNOTS_V2_HEADER_HEX).unwrap();
        bitcoin::consensus::deserialize(&raw).unwrap()
    }

    fn record_of(prev_fk: Fk, header: &Header) -> HeaderRecord {
        HeaderRecord {
            prev_fk,
            version: header.version.to_consensus(),
            timestamp: header.time,
            bits: header.bits.to_consensus(),
            nonce: header.nonce,
            merkle_root: header.merkle_root.to_byte_array(),
            hash: header.block_hash().to_byte_array(),
            v2: header.v2,
            size: 0,
            weight: 0,
        }
    }

    #[test]
    fn header_record_v2_roundtrip_keeps_extension_and_hash() {
        let header = knots_v2_header();
        assert_eq!(header.block_hash().to_string(), KNOTS_V2_BLOCK_HASH);
        let rec = record_of(Fk::NULL, &header);
        let enc = rec.encode();
        assert_eq!(
            u32::from_le_bytes(enc[8..12].try_into().unwrap()) & Header::V2_VERSION_FLAG,
            Header::V2_VERSION_FLAG,
            "the version column carries the v2 flag"
        );
        assert_eq!(
            &enc[12..16],
            &header.time.to_le_bytes(),
            "consensus time in the row"
        );
        let back = HeaderRecord::decode(&enc).unwrap();
        assert_eq!(back, rec);
        assert_eq!(back.version, header.version.to_consensus());
        assert_eq!(back.header_size(), 164);
        let rebuilt = back.wire_header(&header.prev_blockhash.to_byte_array());
        assert_eq!(rebuilt, header);
        assert_eq!(
            back.block_hash(&header.prev_blockhash.to_byte_array()),
            rec.hash
        );
    }

    #[test]
    fn ensure_checks_a_v2_child_by_its_blake2b_hash() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        let header = knots_v2_header();
        let parent = sample(header.prev_blockhash.to_byte_array());
        let parent_fk = t.ensure(&parent).unwrap();
        let child = record_of(parent_fk, &header);
        let child_fk = t.ensure(&child).unwrap();
        assert_ne!(child_fk, parent_fk);
        let got = t.get(child_fk).unwrap();
        assert_eq!(got.v2, header.v2);
        assert_eq!(got.hash, header.block_hash().to_byte_array());

        let mut false_edge = child.clone();
        false_edge.hash[0] ^= 1;
        assert!(
            t.ensure(&false_edge).is_err(),
            "a v2 child is checked with the v2 hash"
        );
        let mut sha256d_hash = child.clone();
        sha256d_hash.hash = block_header_hash(
            child.version,
            &parent.hash,
            &child.merkle_root,
            child.timestamp,
            child.bits,
            child.nonce,
        );
        assert!(
            t.ensure(&sha256d_hash).is_err(),
            "sha256d of the prefix is not the v2 hash"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrite_v26_header_body_widens_rows() {
        let dir = tmp();
        let rec = sample([0x22; 32]);
        {
            let body = TableFile::create(dir.join("header.body"), TableKind::Header).unwrap();
            let raw = rec.encode();
            body.write_at(FILE_HEADER_LEN as u64, &raw[..HEADER_RECORD_LEN_V26])
                .unwrap();
            body.set_logical_len(FILE_HEADER_LEN as u64 + HEADER_RECORD_LEN_V26 as u64)
                .unwrap();
            body.flush().unwrap();
            let h = HashHead::create_with_slots(dir.join("header.head"), 64).unwrap();
            h.insert(&rec.hash, Fk(1)).unwrap();
            h.flush().unwrap();
        }
        assert!(
            HeaderTable::open_tiny(&dir).is_err(),
            "an 88 B body does not open as-is"
        );
        HeaderTable::rewrite_v26_body_to_172(&dir).unwrap();
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(t.get(Fk(1)).unwrap(), rec);
        assert_eq!(t.count(), 1);
        drop(t);
        HeaderTable::rewrite_v26_body_to_172(&dir).unwrap();
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(t.get(Fk(1)).unwrap(), rec, "already 172 B is a no-op");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrite_v24_header_body_strips_size_weight() {
        let dir = tmp();
        let rec = sample([0x11; 32]);
        {
            let body = TableFile::create(dir.join("header.body"), TableKind::Header).unwrap();
            let mut raw = [0u8; HEADER_RECORD_LEN_V24];
            raw[..HEADER_RECORD_LEN_V26].copy_from_slice(&rec.encode()[..HEADER_RECORD_LEN_V26]);
            raw[88..92].copy_from_slice(&285u32.to_le_bytes());
            raw[92..96].copy_from_slice(&1140u32.to_le_bytes());
            body.write_at(FILE_HEADER_LEN as u64, &raw).unwrap();
            body.set_logical_len(FILE_HEADER_LEN as u64 + HEADER_RECORD_LEN_V24 as u64)
                .unwrap();
            body.flush().unwrap();
            let h = HashHead::create_with_slots(dir.join("header.head"), 64).unwrap();
            h.insert(&rec.hash, Fk(1)).unwrap();
            h.flush().unwrap();
        }
        HeaderTable::rewrite_v24_body_to_88(&dir).unwrap();
        HeaderTable::rewrite_v26_body_to_172(&dir).unwrap();
        let t = HeaderTable::open_tiny(&dir).unwrap();
        let got = t.get(Fk(1)).unwrap();
        assert_eq!(got.hash, rec.hash);
        assert_eq!(got.size, 0);
        assert_eq!(got.weight, 0);
        assert_eq!(t.count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_head_occupied_sums_base_and_gen() {
        let dir = tmp();
        assert_eq!(header_head_occupied(&dir).unwrap(), 0);
        {
            let h = HashHead::create_with_slots(dir.join("header.head"), 64).unwrap();
            h.insert(&[0x11; 32], Fk(1)).unwrap();
            h.flush().unwrap();
        }
        assert_eq!(header_head_occupied(&dir).unwrap(), 1);
        {
            let g = HashHead::create_with_slots(dir.join("header.head.g1"), 64).unwrap();
            g.insert(&[0x22; 32], Fk(2)).unwrap();
            g.insert(&[0x33; 32], Fk(3)).unwrap();
            g.flush().unwrap();
        }
        assert_eq!(header_head_occupied(&dir).unwrap(), 3);
        std::fs::write(dir.join("header.head"), [0u8; 3]).unwrap();
        assert!(header_head_occupied(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewrite_v24_already_88_is_nop() {
        let dir = tmp();
        let t = HeaderTable::create_tiny(&dir).unwrap();
        t.ensure(&sample([0x22; 32])).unwrap();
        t.flush().unwrap();
        drop(t);
        HeaderTable::rewrite_v24_body_to_88(&dir).unwrap();
        HeaderTable::rewrite_v26_body_to_172(&dir).unwrap();
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(t.count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 11×96 B is the same byte length as 12×88 B. Occupied 11 must strip.
    #[test]
    fn rewrite_v24_ambiguous_96_strips_each_row() {
        let dir = tmp();
        let n = 11u64;
        let recs: Vec<HeaderRecord> = (0..n).map(|i| sample([0xA0 + i as u8; 32])).collect();
        {
            let body = TableFile::create(dir.join("header.body"), TableKind::Header).unwrap();
            let mut blob = Vec::with_capacity(n as usize * HEADER_RECORD_LEN_V24);
            for rec in &recs {
                let mut raw = [0u8; HEADER_RECORD_LEN_V24];
                raw[..HEADER_RECORD_LEN_V26]
                    .copy_from_slice(&rec.encode()[..HEADER_RECORD_LEN_V26]);
                raw[88..92].copy_from_slice(&7u32.to_le_bytes());
                blob.extend_from_slice(&raw);
            }
            body.write_at(FILE_HEADER_LEN as u64, &blob).unwrap();
            body.set_logical_len(FILE_HEADER_LEN as u64 + blob.len() as u64)
                .unwrap();
            body.flush().unwrap();
            let h = HashHead::create_with_slots(dir.join("header.head"), 64).unwrap();
            for (i, rec) in recs.iter().enumerate() {
                h.insert(&rec.hash, Fk(i as u64 + 1)).unwrap();
            }
            h.flush().unwrap();
        }
        HeaderTable::rewrite_v24_body_to_88(&dir).unwrap();
        HeaderTable::rewrite_v26_body_to_172(&dir).unwrap();
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(t.count(), n);
        for (i, rec) in recs.iter().enumerate() {
            let got = t.get(Fk(i as u64 + 1)).unwrap();
            assert_eq!(got.hash, rec.hash);
            assert_eq!(got.size, 0);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 12×88 B is the same byte length as 11×96 B. Occupied 12 must not strip.
    #[test]
    fn rewrite_v24_ambiguous_88_stays() {
        let dir = tmp();
        let n = 12u64;
        let recs: Vec<HeaderRecord> = (0..n).map(|i| sample([0xB0 + i as u8; 32])).collect();
        {
            let body = TableFile::create(dir.join("header.body"), TableKind::Header).unwrap();
            let mut blob = Vec::with_capacity(n as usize * HEADER_RECORD_LEN_V26);
            for rec in &recs {
                blob.extend_from_slice(&rec.encode()[..HEADER_RECORD_LEN_V26]);
            }
            body.write_at(FILE_HEADER_LEN as u64, &blob).unwrap();
            body.set_logical_len(FILE_HEADER_LEN as u64 + blob.len() as u64)
                .unwrap();
            body.flush().unwrap();
            let h = HashHead::create_with_slots(dir.join("header.head"), 64).unwrap();
            for (i, rec) in recs.iter().enumerate() {
                h.insert(&rec.hash, Fk(i as u64 + 1)).unwrap();
            }
            h.flush().unwrap();
        }
        let before = std::fs::metadata(dir.join("header.body")).unwrap().len();
        HeaderTable::rewrite_v24_body_to_88(&dir).unwrap();
        HeaderTable::rewrite_v26_body_to_172(&dir).unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("header.body")).unwrap().len(),
            before + n * (HEADER_RECORD_LEN - HEADER_RECORD_LEN_V26) as u64,
            "v24 keeps every row; the widen adds the v2 tail to each"
        );
        let t = HeaderTable::open_tiny(&dir).unwrap();
        assert_eq!(t.count(), n);
        assert_eq!(t.get(Fk(n)).unwrap().hash, recs[n as usize - 1].hash);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
