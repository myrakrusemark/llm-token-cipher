#!/bin/bash
# Example usage of the LLM Token Cipher

echo "=== LLM Token Cipher Demo ==="
echo

echo "1. Encoding a secret message..."
echo "   Secret: 'SECRET:Meet at midnight'"
echo "   Cover: 'I heard that'"
echo

python3 token_cipher.py encode "SECRET:Meet at midnight" "SECRET:" "I heard that" --sentinel " Goodbye." --quiet > encoded.txt

echo "Encoded output:"
cat encoded.txt
echo

# Extract ciphertext and offset
CIPHER=$(head -n -1 encoded.txt)
OFFSET=$(tail -n 1 encoded.txt)

echo "Ciphertext: $CIPHER"
echo "Cover offset: $OFFSET"
echo

echo "2. Decoding the message..."
echo "   Using key: 'SECRET:'"
echo "   Using sentinel: ' Goodbye.'"
echo

DECODED=$(python3 token_cipher.py decode "$CIPHER" "SECRET:" --cover-offset $OFFSET --sentinel " Goodbye." --quiet)

echo "Decoded: $DECODED"
echo

if [ "$DECODED" = "SECRET:Meet at midnight" ]; then
    echo "✓ Success! Message decoded correctly."
else
    echo "✗ Decoding failed!"
fi

# Cleanup
rm encoded.txt
