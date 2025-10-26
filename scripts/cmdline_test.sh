#!/bin/sh


for size in $(seq 262000 1 262274); do
    yes a | head -c "$size" > /tmp/test.txt
    czip -c /tmp/test.txt > /tmp/test.txt.cz
    czip -dc /tmp/test.txt.cz > /tmp/test.txt.cmp

    if ! diff /tmp/test.txt /tmp/test.txt.cmp >/dev/null; then
        echo "Test failed for size $size"
        exit 1
    fi

    rm /tmp/test.txt /tmp/test.txt.cz /tmp/test.txt.cmp
done

echo "Success! All tests passed."

