// DTLS can send handshake messages in a fragmented format,
// thus, we expect something like the following to come over the wire;
// > FO: fragment offset, FL: Fragment Length, L: Shorthand for "message length",
// > "FL=?": a fragment length other than L
//
//  [SEQ=1, FO=0, FL=L] (A full handshake message)
//  [SEQ=2, FO=0, FL=L]
//  [SEQ=3, FO=0, FL=?] (the first part of a fragmented message)
//  [SEQ=3, FO=?, FL=?]
//  [SEQ=3, FO=?, FL=?, FO+FL=L] (Last part of the fragmented message)
//  [SEQ=4, FO=0, FL=L] (A normal full message)

// TODO: probably not final design,
// probably want to play with enums (Fragmented(T), Full(T))

// The fragmenter takes a series of messages and
// possibly splits them up if their payload exceeds their max length
pub struct Fragmenter {

}

// The defragmenter holds continuous ranges of bytes in cache,
// keeps track of which ranges were seen, and when possible,
// defragments them to one final message.
pub struct Dragmenter {

}