#!/usr/bin/env python3
"""
Token Cipher - Steganographic encoding with key context

Encode: "Secret Key: Secret Message" + cover → "Another time, when I went shopping"
Decode: "Another time..." + Key "Secret Key: " → "Secret Key: Secret Message"

The ciphertext looks completely innocent. Only the key reveals the message!
"""

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
import argparse
import sys
from typing import List


class TokenCipher:
    def __init__(self, model_name: str = "gpt2"):
        """Initialize with a language model"""
        print(f"Loading model: {model_name}...", file=sys.stderr)
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(model_name)
        self.model.eval()
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model.to(self.device)
        print(f"Model loaded on {self.device}\n", file=sys.stderr)

    def extract_pattern_from_text(self, text: str, start_token_idx: int = 0) -> List[int]:
        """Extract rank pattern from text starting at position"""
        input_ids = self.tokenizer.encode(text, return_tensors="pt").to(self.device)
        ranks = []

        for i in range(start_token_idx + 1, len(input_ids[0])):
            context = input_ids[:, :i]

            with torch.no_grad():
                outputs = self.model(context)
                logits = outputs.logits[0, -1, :]
                probs_dist = torch.softmax(logits, dim=-1)

            actual_token_id = input_ids[0, i].item()
            sorted_probs, sorted_indices = torch.sort(probs_dist, descending=True)
            rank = (sorted_indices == actual_token_id).nonzero(as_tuple=True)[0].item() + 1

            ranks.append(rank)

        return ranks

    def apply_pattern(self, start_text: str, pattern: List[int], hidden_context: str = "") -> str:
        """
        Apply rank pattern starting from given text

        Args:
            start_text: Visible text to start with (will be in output)
            pattern: Rank sequence to apply
            hidden_context: Hidden left context (affects logits but not output)
        """
        # Visible tokens (will be emitted)
        if start_text:
            visible_ids = list(self.tokenizer.encode(start_text, return_tensors="pt")[0].cpu().numpy())
        else:
            visible_ids = []

        # Hidden tokens (left context for logits only, never emitted)
        if hidden_context:
            hidden_ids = list(self.tokenizer.encode(hidden_context, return_tensors="pt")[0].cpu().numpy())
        else:
            hidden_ids = []

        generated = visible_ids[:]  # What we will decode/return

        for rank in pattern:
            # Context for logits = hidden + visible_so_far
            if hidden_ids or generated:
                ctx = torch.tensor([hidden_ids + generated]).to(self.device)
            else:
                dummy_token = self.tokenizer.bos_token_id if self.tokenizer.bos_token_id is not None else 50256
                ctx = torch.tensor([[dummy_token]]).to(self.device)

            with torch.no_grad():
                outputs = self.model(ctx)
                logits = outputs.logits[0, -1, :]
                probs = torch.softmax(logits, dim=-1)

            sorted_probs, sorted_indices = torch.sort(probs, descending=True)
            chosen_idx = min(rank - 1, len(sorted_indices) - 1)
            next_token_id = sorted_indices[chosen_idx].item()

            generated.append(next_token_id)

        return self.tokenizer.decode(generated)

    def apply_rank_step(self, generated_ids: List[int], rank: int, hidden_ids: List[int]) -> List[int]:
        """
        Apply a single rank step (for streaming decode)

        Args:
            generated_ids: Current generated token IDs
            rank: Rank to select
            hidden_ids: Hidden context token IDs

        Returns:
            Updated generated_ids with new token appended
        """
        if hidden_ids or generated_ids:
            ctx = torch.tensor([hidden_ids + generated_ids]).to(self.device)
        else:
            dummy_token = self.tokenizer.bos_token_id if self.tokenizer.bos_token_id is not None else 50256
            ctx = torch.tensor([[dummy_token]]).to(self.device)

        with torch.no_grad():
            logits = self.model(ctx).logits[0, -1, :]
            probs = torch.softmax(logits, dim=-1)

        sorted_indices = torch.sort(probs, descending=True).indices
        next_id = sorted_indices[min(rank - 1, len(sorted_indices) - 1)].item()
        generated_ids.append(next_id)
        return generated_ids

    def encode(self, full_message: str, key: str, cover_start: str, sentinel: str = "END", verbose: bool = True) -> tuple:
        """
        Encode a message with key context

        Args:
            full_message: "Secret Key: Secret Message"
            key: "Secret Key: " (the context)
            cover_start: "The weather" (what to start ciphertext with)
            sentinel: End marker (e.g., "END", "Goodbye.", etc.)

        Returns:
            (ciphertext, cover_token_count) - tuple of innocent-looking ciphertext and cover length
        """
        if not full_message.startswith(key):
            raise ValueError(f"Message must start with key!\nMessage: {repr(full_message)}\nKey: {repr(key)}")

        secret_part = full_message[len(key):]

        # Append sentinel to secret for termination
        secret_with_sentinel = secret_part + sentinel
        full_with_sentinel = key + secret_with_sentinel

        if verbose:
            print("="*70, file=sys.stderr)
            print("ENCODING", file=sys.stderr)
            print("="*70, file=sys.stderr)
            print(f"Full message: {repr(full_message)}", file=sys.stderr)
            print(f"Key: {repr(key)}", file=sys.stderr)
            print(f"Secret part: {repr(secret_part)}", file=sys.stderr)
            print(f"Sentinel: {repr(sentinel)}", file=sys.stderr)
            print(f"With sentinel: {repr(secret_with_sentinel)}", file=sys.stderr)
            print(f"Cover start: {repr(cover_start)}", file=sys.stderr)

        # Extract pattern from (key + secret + sentinel) starting after the key
        # This way the key provides context for scoring
        key_tokens = len(self.tokenizer.encode(key))
        pattern = self.extract_pattern_from_text(full_with_sentinel, start_token_idx=key_tokens - 1)

        if verbose:
            print(f"\nPattern length: {len(pattern)}", file=sys.stderr)
            print(f"Pattern sample: {pattern[:15]}...", file=sys.stderr)

        # Apply pattern with key as hidden context
        # The key affects logits but doesn't appear in output
        ciphertext = self.apply_pattern(cover_start, pattern, hidden_context=key)

        # Calculate cover token count
        cover_token_count = len(self.tokenizer.encode(cover_start, add_special_tokens=False))

        if verbose:
            print(f"\n{'='*70}", file=sys.stderr)
            print("CIPHERTEXT:", file=sys.stderr)
            print(f"{'='*70}", file=sys.stderr)
            print(f"Cover token count: {cover_token_count}", file=sys.stderr)

        return ciphertext, cover_token_count

    def decode(self, ciphertext: str, key: str, cover_token_count: int = 0, sentinel: str = "END", verbose: bool = True) -> str:
        """
        Decode ciphertext using key and cover offset (streaming with sentinel detection)

        Args:
            ciphertext: "Another time, when I went shopping"
            key: "Secret Key: "
            cover_token_count: Number of tokens to skip at start of ciphertext (the cover)
            sentinel: End marker to detect (must match encoding sentinel)

        Returns:
            Full plaintext message "Secret Key: Secret Message"
        """
        if verbose:
            print("="*70, file=sys.stderr)
            print("DECODING (streaming)", file=sys.stderr)
            print("="*70, file=sys.stderr)
            print(f"Ciphertext: {repr(ciphertext)}", file=sys.stderr)
            print(f"Key: {repr(key)}", file=sys.stderr)
            print(f"Sentinel: {repr(sentinel)}", file=sys.stderr)

        # Tokenize
        cipher_ids = self.tokenizer.encode(ciphertext, add_special_tokens=False)
        key_ids = self.tokenizer.encode(key, add_special_tokens=False)
        sentinel_ids = self.tokenizer.encode(sentinel, add_special_tokens=False)
        combined_ids = key_ids + cipher_ids

        if verbose:
            print(f"Key length: {len(key_ids)} tokens", file=sys.stderr)
            print(f"Ciphertext length: {len(cipher_ids)} tokens", file=sys.stderr)
            print(f"Cover token count: {cover_token_count}", file=sys.stderr)
            print(f"Sentinel length: {len(sentinel_ids)} tokens", file=sys.stderr)
            print(f"Total to process: {len(combined_ids)} tokens", file=sys.stderr)

        # Stream: extract ranks and apply them one at a time
        # Skip the cover tokens at the start of ciphertext
        secret_ids = []
        sentinel_len = len(sentinel_ids)
        start_pos = len(key_ids) + cover_token_count

        if verbose:
            print(f"\nStarting decode from position {start_pos} (skipping {cover_token_count} cover tokens)...", file=sys.stderr)
            print(f"Streaming decode (stopping at sentinel {repr(sentinel)})...", file=sys.stderr)

        for i in range(start_pos, len(combined_ids)):
            # Extract rank for this position
            context = combined_ids[:i]
            actual_token_id = combined_ids[i]

            # Get logits from context
            ctx_tensor = torch.tensor([context]).to(self.device)
            with torch.no_grad():
                logits = self.model(ctx_tensor).logits[0, -1, :]
                probs = torch.softmax(logits, dim=-1)

            # Find rank of actual token
            sorted_indices = torch.sort(probs, descending=True).indices
            rank = (sorted_indices == actual_token_id).nonzero(as_tuple=True)[0].item() + 1

            # Apply this rank with KEY as hidden context (matching encode!)
            # Must use same hidden context as encoding to get exact reconstruction
            self.apply_rank_step(secret_ids, rank, hidden_ids=key_ids)

            # Check if we've hit the sentinel
            if len(secret_ids) >= sentinel_len:
                if secret_ids[-sentinel_len:] == sentinel_ids:
                    if verbose:
                        print(f"Sentinel detected at position {i}!", file=sys.stderr)
                    break

        # Strip sentinel
        if len(secret_ids) >= sentinel_len and secret_ids[-sentinel_len:] == sentinel_ids:
            secret_ids = secret_ids[:-sentinel_len]

        secret_part = self.tokenizer.decode(secret_ids)

        if verbose:
            print(f"Decoded secret: {repr(secret_part)}", file=sys.stderr)

        # Prepend key to get full message
        full_message = key + secret_part

        if verbose:
            print(f"\n{'='*70}", file=sys.stderr)
            print("FULL PLAINTEXT:", file=sys.stderr)
            print(f"{'='*70}", file=sys.stderr)

        return full_message


def main():
    parser = argparse.ArgumentParser(
        description="Token Cipher - Context-based steganography",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encode
  python token_cipher_final.py encode "Secret Key: Meet at midnight" "Secret Key: " "The weather"

  Output: "The weather is nice today..." (innocent text)

  # Decode with correct key
  python token_cipher_final.py decode "The weather is nice today..." "Secret Key: "

  Output: "Secret Key: Meet at midnight"

  # Decode with wrong key - garbage!
  python token_cipher_final.py decode "The weather is nice today..." "Secret"

  Output: "[plausible but wrong text]"
        """
    )

    parser.add_argument("command", choices=["encode", "decode"])
    parser.add_argument("text", help="Full message (encode) or Ciphertext (decode)")
    parser.add_argument("key", help="Secret key context")
    parser.add_argument("cover", nargs="?", help="Cover start text (encode only)")
    parser.add_argument("--cover-offset", type=int, help="Cover token count (decode only, required)")
    parser.add_argument("--sentinel", default="END", help="End marker (default: 'END')")
    parser.add_argument("--model", default="gpt2", help="Model name")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")

    args = parser.parse_args()

    cipher = TokenCipher(args.model)

    if args.command == "encode":
        cover = args.cover if args.cover else ""
        ciphertext, cover_token_count = cipher.encode(args.text, args.key, cover, sentinel=args.sentinel, verbose=not args.quiet)

        # Output format: ciphertext (possibly multiline), then offset on last line
        print(ciphertext)
        print(cover_token_count)

        if not args.quiet:
            print(f"\n--- DECODE INFO ---", file=sys.stderr)
            print(f"Key: {repr(args.key)}", file=sys.stderr)
            print(f"Sentinel: {repr(args.sentinel)}", file=sys.stderr)
    else:
        # For decode, need cover_token_count
        if args.cover_offset is None:
            print("Error: decode requires --cover-offset", file=sys.stderr)
            sys.exit(1)
        result = cipher.decode(args.text, args.key, cover_token_count=args.cover_offset, sentinel=args.sentinel, verbose=not args.quiet)
        # Just output the decoded message (key + message, sentinel already stripped)
        print(result)


if __name__ == "__main__":
    main()
