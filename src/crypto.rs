use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// 32 bytes of OS CSPRNG entropy, base58-encoded (no 0/O/I/l — safe to copy by eye).
/// This is the *identity* secret (agent token / admin token). Authorization is a
/// separate concept (session grants) — invariant 5: secret ≠ session token.
pub fn gen_token() -> String {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    bs58::encode(b).into_string()
}

/// Typed random id: `req_...` / `ses_...` — 16 bytes of entropy, prefix prevents
/// ids from being swapped between roles (see ADR-0012).
pub fn gen_id(prefix: &str) -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{}_{}", prefix, bs58::encode(b).into_string())
}

/// 16 random bytes, hex — one-time nonce for request signing.
pub fn gen_nonce() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub fn hmac_hex(key: &str, msg: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("hmac accepts any key length");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time equality — never short-circuits on the first differing byte.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Canonical string that is signed by the agent: everything that must be
/// integrity-protected. Note: `path` excludes the query string (documented contract).
pub fn signing_payload(ts: &str, nonce: &str, method: &str, path: &str, body_sha256_hex: &str) -> String {
    format!("{ts}\n{nonce}\n{method}\n{path}\n{body_sha256_hex}")
}

// ============================================================
// v1.1.0 (ADR-0025): device identity material
// ============================================================

/// Crockford base32 alphabet — excludes 0/O/1/I so IDs survive being read aloud
/// or typed by hand (research R4).
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Alphabet index of a Crockford char (identity for checksums — the index, not
/// the ASCII value, is what the check math runs on).
fn crockford_index(c: u8) -> Option<usize> {
    CROCKFORD.iter().position(|&x| x == c)
}

/// Device id `FAR-XXXX-XXXX`: 7 random Crockford chars + 1 mod-32 check char.
/// A single typo changes the check char → rejected client-side before a network
/// round-trip. Entropy ≈ 35 bits of *identity* space (the secret is the password,
/// not the id).
pub fn gen_device_id() -> String {
    let mut b = [0u8; 7];
    rand::thread_rng().fill_bytes(&mut b);
    let idx: Vec<usize> = b.iter().map(|x| (*x as usize) % 32).collect();
    let check: usize = idx.iter().sum::<usize>() % 32;
    let mut s = String::new();
    for i in 0..7 {
        s.push(CROCKFORD[idx[i]] as char);
    }
    s.push(CROCKFORD[check] as char);
    format!("FAR-{}-{}", &s[0..4], &s[4..8])
}

/// Validate the FAR-XXXX-XXXX shape + check char (typo detection).
pub fn device_id_valid(id: &str) -> bool {
    let body = id.strip_prefix("FAR-").unwrap_or(id);
    let parts: Vec<&str> = body.split('-').collect();
    if parts.len() != 2 || parts[0].len() != 4 || parts[1].len() != 4 {
        return false;
    }
    let joined: String = parts.concat();
    let bytes = joined.as_bytes();
    if bytes.len() != 8 {
        return false;
    }
    let mut sum = 0usize;
    for &c in &bytes[..7] {
        match crockford_index(c) {
            Some(i) => sum += i,
            None => return false,
        }
    }
    match crockford_index(bytes[7]) {
        Some(i) => i == sum % 32,
        None => false,
    }
}

/// 1024-word list for password generation (research R4 §3). Words are short,
/// lowercase, ASCII, and visually distinct — 10 bits of entropy per word.
const WORDS: &[&str] = &[
    "able", "acid", "aged", "also", "area", "army", "away", "baby",
    "back", "ball", "band", "bank", "barn", "base", "bath", "beam",
    "bean", "bear", "beat", "bell", "belt", "bend", "bird", "blow",
    "blue", "boat", "body", "boil", "bold", "bolt", "bomb", "bond",
    "bone", "boom", "boot", "born", "boss", "both", "bowl", "bulk",
    "burn", "bush", "calm", "camp", "card", "care", "case", "cash",
    "cast", "cell", "cent", "chair", "chat", "chin", "cite", "city",
    "club", "coal", "coat", "code", "coin", "cold", "comb", "cook",
    "cool", "copy", "cord", "core", "corn", "cost", "crew", "crop",
    "crown", "cure", "curl", "dare", "dark", "dart", "dash", "data",
    "date", "dawn", "deal", "dear", "debt", "deck", "deep", "deer",
    "desk", "dial", "diet", "dirt", "dish", "dive", "dock", "doctor",
    "dome", "done", "door", "dose", "down", "draw", "drew", "drop",
    "drug", "drum", "duck", "dust", "duty", "each", "earn", "ease",
    "east", "echo", "edge", "else", "emit", "ends", "epic", "even",
    "ever", "evil", "exit", "face", "fact", "fail", "fair", "fall",
    "farm", "fast", "fate", "fear", "feed", "feel", "fern", "fig",
    "file", "fill", "film", "find", "fine", "fire", "firm", "fish",
    "flag", "flat", "flew", "flip", "flow", "fold", "folk", "food",
    "foot", "fork", "form", "fort", "four", "free", "frog", "fuel",
    "full", "fund", "gain", "game", "gate", "gave", "gear", "gift",
    "girl", "give", "glad", "glow", "goal", "goat", "gold", "golf",
    "gone", "good", "grab", "gray", "grew", "grid", "grin", "grip",
    "grow", "guard", "guess", "guest", "guide", "halt", "harm", "harp",
    "hash", "haul", "have", "haze", "heap", "hear", "heat", "held",
    "helm", "help", "herb", "hero", "high", "hill", "hint", "hold",
    "home", "hook", "hope", "horn", "host", "hour", "huge", "hunt",
    "hurry", "icon", "idea", "inch", "index", "into", "iron", "item",
    "jazz", "join", "joke", "jump", "jury", "just", "keen", "keep",
    "kick", "kind", "king", "kiss", "kite", "knee", "knew", "know",
    "lace", "lack", "lady", "laid", "lake", "land", "lane", "last",
    "late", "lawn", "lazy", "lead", "leaf", "lean", "left", "lend",
    "less", "lift", "like", "lime", "line", "link", "lion", "list",
    "live", "load", "loan", "lock", "logo", "long", "look", "loop",
    "lord", "loss", "lost", "loud", "love", "luck", "lunch", "made",
    "mail", "main", "make", "male", "many", "map", "mark", "mask",
    "mass", "mate", "maze", "meal", "mean", "meat", "meet", "menu",
    "mesh", "mile", "milk", "mill", "mind", "mine", "minor", "mint",
    "miss", "mode", "mole", "moon", "more", "moss", "most", "move",
    "much", "must", "name", "navy", "near", "neat", "neck", "need",
    "news", "next", "nice", "nine", "node", "noise", "none", "north",
    "note", "noun", "oath", "obey", "open", "pace", "pack", "page",
    "paid", "palm", "park", "part", "pass", "past", "path", "peak",
    "pear", "peer", "pick", "pile", "pine", "pink", "pipe", "plan",
    "play", "plot", "plug", "plus", "poem", "poet", "poll", "pond",
    "pool", "port", "post", "pour", "pray", "pull", "pump", "pure",
    "push", "quit", "race", "rack", "ramp", "range", "rare", "rate",
    "read", "reef", "rely", "rest", "rice", "rich", "ride", "ring",
    "rise", "risk", "road", "rock", "roll", "roof", "room", "root",
    "rope", "rose", "rough", "ruby", "rule", "rush", "safe", "sage",
    "sail", "salt", "sand", "save", "scan", "seal", "seat", "seed",
    "seek", "self", "sell", "send", "ship", "shop", "shot", "show",
    "side", "sign", "silk", "sing", "site", "size", "skin", "skip",
    "slim", "slot", "slow", "snap", "snow", "soft", "soil", "sold",
    "sole", "song", "soon", "sort", "soul", "spin", "spot", "star",
    "stay", "stem", "step", "stop", "such", "suit", "sure", "surf",
    "swap", "swim", "tail", "take", "tale", "talk", "tall", "tank",
    "tape", "task", "team", "tell", "tend", "term", "test", "text",
    "than", "that", "them", "then", "they", "thin", "this", "tide",
    "tile", "till", "time", "tiny", "tips", "tire", "toast", "today",
    "told", "tone", "took", "tool", "tops", "torn", "tour", "town",
    "trail", "trap", "tree", "trim", "trip", "true", "tube", "tune",
    "turn", "twin", "type", "unit", "upon", "used", "user", "vast",
    "very", "view", "void", "vote", "wage", "wait", "wake", "walk",
    "wall", "want", "warm", "warn", "wash", "wave", "wear", "week",
    "well", "west", "what", "when", "whom", "wide", "wild", "will",
    "wind", "wine", "wing", "wire", "wise", "wish", "wood", "word",
    "wore", "work", "yard", "year", "zero", "zone", "aim", "ace",
    "act", "add", "age", "aid", "air", "ale", "and", "ant",
    "any", "ape", "arc", "apt", "art", "ash", "ask", "awe",
    "axe", "bad", "bag", "ban", "bar", "bat", "bay", "bed",
    "bee", "bet", "bid", "bib", "bin", "bit", "boa", "bob",
    "bog", "boo", "bow", "box", "bra", "bud", "bug", "bun",
    "bus", "but", "buy", "cab", "cad", "cam", "can", "cap",
    "car", "cat", "caw", "cob", "cod", "cog", "cop", "cot",
    "cow", "coy", "cub", "cue", "cup", "cur", "dab", "dam",
    "day", "den", "dew", "did", "dig", "dim", "din", "dip",
    "dob", "doe", "dog", "don", "dot", "dry", "dub", "dud",
    "due", "dug", "duo", "dye", "ear", "eat", "ebb", "ego",
    "elf", "elk", "elm", "emu", "end", "err", "eve", "ewe",
    "eye", "fad", "fan", "far", "fat", "fax", "fed", "fee",
    "few", "fin", "fir", "fit", "fix", "flu", "fly", "fob",
    "foe", "fog", "for", "fox", "fry", "fun", "fur", "gag",
    "gap", "gas", "gel", "gem", "get", "gig", "gin", "gnu",
    "god", "got", "gum", "gun", "gut", "gym", "had", "hag",
    "ham", "has", "hat", "haw", "hem", "hen", "her", "hew",
    "hid", "him", "hip", "his", "hit", "hob", "hoe", "hog",
    "hop", "hot", "how", "hub", "hue", "hug", "hum", "hut",
    "ice", "icy", "ill", "imp", "ink", "inn", "ion", "ire",
    "irk", "its", "ivy", "jab", "jam", "jar", "jaw", "jay",
    "jet", "jig", "job", "jog", "jot", "joy", "jug", "keg",
    "key", "kid", "kin", "kit", "lab", "lad", "lag", "lap",
    "law", "lax", "lay", "led", "leg", "let", "lid", "lie",
    "lip", "lit", "lob", "log", "lot", "low", "lug", "lye",
    "mad", "man", "mar", "mat", "maw", "may", "men", "met",
    "mew", "mid", "mix", "mob", "mod", "mop", "mow", "mud",
    "mug", "nab", "nag", "nap", "nay", "net", "new", "nil",
    "nim", "nip", "nor", "not", "now", "nub", "nun", "nut",
    "oak", "oar", "oat", "odd", "ode", "off", "oft", "oil",
    "old", "one", "opt", "orb", "ore", "our", "out", "owe",
    "owl", "own", "pad", "pal", "pan", "pap", "par", "pat",
    "paw", "pay", "pea", "peg", "pen", "pep", "per", "pet",
    "pew", "pie", "pig", "pin", "pit", "ply", "pod", "pot",
    "pox", "pro", "pry", "pub", "pug", "pun", "pup", "put",
    "rag", "ram", "ran", "rap", "rat", "raw", "ray", "red",
    "rib", "rid", "rig", "rim", "rip", "rob", "rod", "roe",
    "rot", "row", "rub", "rug", "rum", "run", "rut", "rye",
    "sag", "sap", "sat", "saw", "sax", "say", "sea", "see",
    "sew", "she", "shy", "sin", "sip", "sir", "sit", "six",
    "ski", "sky", "sly", "sob", "sod", "son", "sow", "soy",
    "spa", "spy", "sty", "sub", "sue", "sum", "sun", "tab",
    "tad", "tag", "tan", "tap", "tar", "tax", "tea", "ted",
    "ten", "the", "thy", "tie", "tin", "tip", "toe", "ton",
    "too", "top", "tot", "tow", "toy", "try", "tub", "tug",
    "tux", "two", "urn", "use", "van", "vat", "vet", "via",
    "vie", "vow", "wad", "wag", "wan", "war", "wax", "web",
    "wed", "wee", "wet", "who", "why", "wig", "win", "wit",
    "woe", "wok", "won", "woo", "wow", "yak", "yam", "yap",
    "yaw", "yea", "yes", "yet", "yew", "you", "zag", "zap",
    "zed", "zen", "zip", "zoo", "amber", "anchor", "angle", "ankle",
    "apple", "april", "arrow", "ashen", "aspen", "atlas", "badge", "bagel",
    "baker", "balloon", "bamboo", "banana", "banjo", "basin", "basket", "batch",
    "beach", "beard", "beast", "bench", "berry", "birth", "bison", "blade",
    "blank", "blast", "blaze", "blend", "bliss", "block", "blond", "blood",
    "bloom", "blouse", "brave", "brick", "bride", "brief", "bring", "brisk",
    "broad", "broom", "brook", "brown", "brush", "build", "built", "bunch",
    "bunny", "burger", "buyer", "cabin", "cable", "cactus", "camel", "candle",
    "candy", "canvas", "cargo", "carve", "catch", "cedar", "chain", "chalk",
];

/// Auto-generated device password: 5 words + 2 decimal digits, `-`-joined
/// (e.g. `harbor-tiger-42-blue-quantum`). Entropy ≈ 5×log2(1024) + log2(90)
/// ≈ **56.6 bits** (ADR-0025 §3). Not a human-chosen secret; Argon2 + backoff
/// carry the brute-force defense.
pub fn gen_password() -> String {
    let mut parts: Vec<String> = (0..5)
        .map(|_| {
            let mut b = [0u8; 2];
            rand::thread_rng().fill_bytes(&mut b);
            let idx = (((b[0] as u16) << 8 | b[1] as u16) % 1024) as usize;
            WORDS[idx].to_string()
        })
        .collect();
    let mut n = [0u8; 1];
    rand::thread_rng().fill_bytes(&mut n);
    parts.push((10 + (n[0] as u16 % 90)).to_string()); // 10–99, leading digit never 0
    parts.join("-")
}

/// Argon2id (m=64 MiB, t=3, p=1 — OWASP floor 19 MiB/t=2/p=1 exceeded, ADR-0025).
/// Output is the PHC string (algorithm + params + salt + hash) — self-describing
/// and verifiable by `password_verify`.
pub fn password_hash(password: &str) -> anyhow::Result<String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    let params = argon2::Params::new(64 * 1024, 3, 1, None)
        .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let out = a
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;
    Ok(out.to_string())
}

/// Verify a password against a stored PHC string (Argon2id). Runs ONLY on the
/// login endpoint — never per request (ADR-0025 §2).
pub fn password_verify(stored_phc: &str, password: &str) -> bool {
    use argon2::password_hash::{PasswordVerifier};
    let parsed = match argon2::PasswordHash::new(stored_phc) {
        Ok(p) => p,
        Err(_) => return false,
    };
    argon2::Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

/// 256-bit device key (the per-request HMAC key after login) — same format as
/// `gen_token()` so every existing HMAC/rotation code path is reusable.
pub fn gen_device_key() -> String {
    gen_token()
}

/// SHA-256 fingerprint of a DER cert, SSH-style presentation:
/// `SHA256:base64-no-padding` (ADR-0025 §4).
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    use base64::Engine;
    let digest = {
        let mut h = Sha256::new();
        h.update(cert_der);
        h.finalize()
    };
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    format!("SHA256:{b64}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // RFC 6234 / FIPS 180-2 test vector
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hmac_known_vector() {
        // RFC 4231 test case 2
        assert_eq!(
            hmac_hex("key", "The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq(b"same", b"same"));
        assert!(!ct_eq(b"same", b"samf"));
        assert!(!ct_eq(b"same", b"longer"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn token_format_and_uniqueness() {
        let t1 = gen_token();
        let t2 = gen_token();
        assert_eq!(t1.len(), t1.chars().count());
        assert!(t1.len() >= 40 && t1.len() <= 46, "base58(32B) ≈ 44 chars: {}", t1.len());
        assert_ne!(t1, t2);
        for c in t1.chars() {
            assert!(!"0OIl".contains(c), "base58 alphabet excludes 0/O/I/l");
        }
    }

    #[test]
    fn id_prefix() {
        let id = gen_id("req");
        assert!(id.starts_with("req_"));
        assert!(id.len() > 10);
    }

    #[test]
    fn signing_payload_shape() {
        let p = signing_payload("100", "n", "POST", "/v1/exec", "aa");
        assert_eq!(p, "100\nn\nPOST\n/v1/exec\naa");
    }

    #[test]
    fn device_id_format_and_checksum() {
        for _ in 0..200 {
            let id = gen_device_id();
            assert_eq!(id.len(), 13, "FAR-XXXX-XXXX = 13 chars: {id}");
            assert!(id.starts_with("FAR-"), "{id}");
            assert!(device_id_valid(&id), "generated id must self-validate: {id}");
            // single-char corruption must break the check char
            let pos = id.rfind(|c: char| c.is_ascii_alphanumeric()).unwrap();
            let mut broken: Vec<char> = id.chars().collect();
            let orig = broken[pos];
            broken[pos] = if orig != 'A' { 'A' } else { 'B' };
            let broken_s: String = broken.into_iter().collect();
            assert!(
                !device_id_valid(&broken_s),
                "typo must be detected: {id} -> {broken_s}"
            );
        }
        assert!(!device_id_valid("FAR-7K2M"));
        assert!(!device_id_valid("SES-7K2M-QX94"));
        assert!(!device_id_valid("FAR-0O0O-0O0O"), "Crockford excludes 0/O");
    }

    #[test]
    fn password_shape_and_entropy_words() {
        for _ in 0..50 {
            let p = gen_password();
            let parts: Vec<&str> = p.split('-').collect();
            assert_eq!(parts.len(), 6, "5 words + number: {p}");
            assert!(parts[5].len() == 2 && parts[5].parse::<u16>().is_ok(), "2-digit suffix: {p}");
            for w in &parts[..5] {
                assert!(WORDS.contains(w), "word must come from the list: {w}");
            }
            let unique: std::collections::HashSet<&&str> = WORDS.iter().collect();
            assert_eq!(unique.len(), WORDS.len(), "wordlist must not repeat words");
        }
    }

    #[test]
    fn argon2_roundtrip_and_reject() {
        let phc = password_hash("correct horse").unwrap();
        assert!(phc.starts_with("$argon2id$"), "PHC string carries algorithm: {phc}");
        assert!(phc.contains("m=65536"), "m=64 MiB: {phc}");
        assert!(phc.contains("t=3"), "t=3: {phc}");
        assert!(phc.contains("p=1"), "p=1: {phc}");
        assert!(password_verify(&phc, "correct horse"));
        assert!(!password_verify(&phc, "wrong battery"));
        assert!(!password_verify("garbage-not-phc", "correct horse"));
    }

    #[test]
    fn fingerprint_shape() {
        let fp = cert_fingerprint(b"der-bytes");
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp.len(), 7 + 43, "sha256 b64 nopad = 43 chars: {}", fp.len());
    }
}
