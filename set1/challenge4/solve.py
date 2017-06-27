""" Detect single-character XOR - https://cryptopals.com/sets/1/challenges/4

One of the 60-character strings in this "file" has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.) 

"""

from codecs import decode, encode
from set1.challenge3.solve import score, brute_force_char

def read_file_lines(filename):
    with open(filename, "r") as f:
        return f.readlines()

if __name__ == "__main__":
    contents = read_file_lines("4.txt")

    for i in range(len(contents)):
        contents[i] = decode(contents[i].replace("\n", ""), "hex")

    results = []
    for line in contents:
        results.append(brute_force_char(line))

    scores = []
    for result in results:
        scores.append(score(result[0][1]))

    print(sorted(scores)[-1:][0][1])