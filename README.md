# LLM Token Cipher

A steganographic cipher that uses Large Language Model (LLM) token probability distributions to encode secret messages into innocent-looking text.

## How It Works

The cipher extracts a "rank pattern" from your secret message (where each token sits in the probability distribution), then applies that pattern with different starting text to generate innocent-looking ciphertext. Only someone with the correct **key**, **cover offset**, and **sentinel** can decode it.

### Example

**Secret:** `"SECRET:Meet at midnight"`
**Cover:** `"I heard that"`
**Ciphertext:** `"I heard that inventor Paul Gall podcast,"`

The ciphertext looks completely normal, but with the right keys, it decodes back to the secret!

## Installation

```bash
pip install torch transformers
```

## Usage

### Encoding a Message

```bash
python3 token_cipher.py encode "KEY:your secret message" "KEY:" "Cover text" --quiet
```

**Output:**
```
Cover text and encoded gibberish
3
```
- Line 1: Ciphertext (can be multiline)
- Line 2: Cover offset (integer)

**Full Example:**
```bash
python3 token_cipher.py encode "SECRET:Meet at midnight" "SECRET:" "I heard that" --sentinel " Goodbye." --quiet
```

**Output:**
```
I heard that inventor Paul Gall podcast,
3
```

### Decoding a Message

You need **four pieces** to decode:
1. **Ciphertext** - the encoded message
2. **Key** - the context prefix (e.g., "SECRET:")
3. **Cover offset** - number of tokens to skip (the integer from encoding)
4. **Sentinel** - the end marker used during encoding

```bash
python3 token_cipher.py decode "ciphertext here" "KEY:" --cover-offset 3 --sentinel " Goodbye." --quiet
```

**Full Example:**
```bash
python3 token_cipher.py decode "I heard that inventor Paul Gall podcast," "SECRET:" --cover-offset 3 --sentinel " Goodbye." --quiet
```

**Output:**
```
SECRET:Meet at midnight
```

## Parameters

### Encoding

- `text` - Full plaintext message (must start with key)
- `key` - Context prefix (e.g., "KEY:", "SECRET:")
- `cover` - Starting text for ciphertext (e.g., "The weather")
- `--sentinel` - End marker (default: "END")
  - Use natural-sounding text: "END", " Goodbye.", etc.
  - Shorter = more natural ciphertext
- `--model` - Model to use (default: "gpt2")
- `--quiet` - Suppress debug output

### Decoding

- `text` - Ciphertext to decode
- `key` - Context prefix (must match encoding)
- `--cover-offset` - Number of cover tokens (from encoding output)
- `--sentinel` - End marker (must match encoding)
- `--model` - Model to use (must match encoding)
- `--quiet` - Suppress debug output

## Sentinel Choice

The **sentinel** is an end marker that tells the decoder when to stop. Choose wisely:

### Good Sentinels (Natural)
- `"END"` - Simple, 1 token
- `" Goodbye."` - Natural ending (2 tokens)
- `" See you soon."` - Conversational (4 tokens)

### Bad Sentinels (Suspicious)
- `"<|ENDSECRET|>"` - Obviously artificial, creates weird tokens
- `"XYZABC"` - Random garbage, high-rank tokens make ciphertext weird

**Rule of thumb:** Keep it natural! The sentinel appears in the ciphertext's probability pattern, so weird sentinels create weird ciphertext.

## Security Model

To decode a message, you need **ALL** of:
1. **Key** - The exact context prefix
2. **Cover offset** - How many tokens to skip
3. **Sentinel** - The exact end marker

Wrong key = wrong output (but still plausible-looking text!)

## Example Workflow

```bash
# Alice encodes
python3 token_cipher.py encode "KEY:Package is at drop point 7" "KEY:" "The weather today" --sentinel " Cheers." --quiet > message.txt

# message.txt contains:
# The weather today seems quite unusual
# 3

# Alice sends Bob:
# - message.txt (ciphertext + offset)
# - Key: "KEY:"
# - Sentinel: " Cheers."

# Bob decodes
CIPHER=$(head -n 1 message.txt)
OFFSET=$(tail -n 1 message.txt)
python3 token_cipher.py decode "$CIPHER" "KEY:" --cover-offset $OFFSET --sentinel " Cheers." --quiet

# Output: KEY:Package is at drop point 7
```

## Advanced Tips

### Longer Covers = More Natural Ciphertext
```bash
# Short cover (1 token)
python3 token_cipher.py encode "KEY:secret" "KEY:" "The" --quiet
# Output: The gibberish

# Long cover (5 tokens)
python3 token_cipher.py encode "KEY:secret" "KEY:" "I was thinking about this" --quiet
# Output: I was thinking about this and continued naturally...
```

### Custom Models
```bash
# Use a different model (must use same model for encode/decode!)
python3 token_cipher.py encode "KEY:secret" "KEY:" "Cover" --model "gpt2-medium" --quiet
python3 token_cipher.py decode "cipher" "KEY:" --cover-offset 1 --model "gpt2-medium" --quiet
```

## Limitations

- **Model-dependent:** Encoder and decoder must use the same model
- **Context-sensitive:** Small changes to key/offset/sentinel produce completely different outputs
- **Not cryptographically secure:** This is steganography (hiding), not encryption
- **Token-based:** Performance depends on how the text tokenizes

## How It Really Works (Technical)

1. **Extract pattern:** Get rank of each token in secret message (with key as context)
2. **Apply pattern:** Use those ranks to select tokens starting from cover text (with key as hidden context)
3. **Decode:** Re-extract ranks from ciphertext (with key context), apply from empty context to reconstruct secret
4. **Stop:** Detect sentinel tokens to know when secret message ends

The key insight: **same ranks + same context = same tokens**, making the transformation reversible!

## License

MIT License - Do whatever you want with it!

## Credits

Created through experimentation with LLM probability distributions and token ranking.
