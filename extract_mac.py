import os
import sys
import matplotlib.pyplot as plt


offsets_found = []
sizes = [i for i in range(5, 33)]
mcs_present = {}
total_cnt = {}
mcs_cnt = []


def extract_length(packet):
    length = int(packet.splitlines()[0].split(': ')[1])
    return length


def extract_payload(packet):
    payload = ""
    lines = packet.splitlines()
    found = False
    for line in lines:
        if ((not found) and ("Payload" not in line)):
            continue
        elif not found:
            found = True
        content = line.strip().split(": ")
        if len(payload) > 0:
            payload += ' '
        payload += content[-1]

    return payload


def parse_mcs(dump):
    lines = dump.splitlines()
    mcs_vals = []
    for i in range(len(lines) - 2):
        if '|MCS|' not in lines[i]:
            continue
        idx = i + 2
        while idx < len(lines):
            mcs_line = lines[idx]
            fields = mcs_line.split('|')
            if len(fields) < 16:
                break
            mcs_val = fields[15].strip()
            if len(mcs_val) > 0:
                mcs_vals.append(int(mcs_val))
            idx += 1
    
    return mcs_vals


def extract_mac_ul(file_path):
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' not found.")
        return [], []
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            data = file.read()
        packets = data.split("\n\n")
        payloads = []
        mcs_values = []
        for i in range(len(packets) - 1):
            packet = packets[i].strip()
            if len(packet) == 0:
                continue
            lines = packet.split("\n")
            if lines and "MAC UL" in lines[0]:
                length = extract_length(packets[i+2])
                if total_cnt.get(length) is None:
                    total_cnt[length] = 1
                else:
                    total_cnt[length] += 1
                # if length < 80:
                #     continue
                payloads.append(extract_payload(packets[i+2]))
                mcs_line_vals = parse_mcs(packets[i])
                mcs_cnt.append((length, len(mcs_line_vals)))
                if len(mcs_line_vals) == 0:
                    payloads.pop()
                else:
                    mcs_values.append(mcs_line_vals[0])
                    if mcs_present.get(length) is None:
                        mcs_present[length] = 1
                    else:
                        mcs_present[length] += 1
        
        return payloads, mcs_values
    
    except Exception as e:
        print(f"Error reading file: {e}")
        return [], []


def byte_to_bits_little_endian(b):
    if not (0 <= b <= 255):
        raise ValueError("Input must be a single byte (0-255).")
    big_endian_bits = f"{b:08b}"
    little_endian_bits = big_endian_bits[::-1]
    return little_endian_bits


def find_mcs_bit_offset(payload_strings, mcs_values):
    results = []
    
    for payload_str, mcs in zip(payload_strings, mcs_values):
        offsets_found.append(set())
        hex_str = payload_str.replace(' ', '')
        bytes_obj = bytes.fromhex(hex_str)
        bitstream = ''.join(f"{byte_to_bits_little_endian(byte)}" for byte in bytes_obj)

        def get_num(idx, n):
            num = 0
            factor = 1
            for i in range(idx, idx + n):
                num += (ord(bitstream[i]) - ord('0')) * factor
                factor <<= 1
            return num

        matches = []

        for i in range(len(bitstream)):
            for n in sizes:
                if i + n <= len(bitstream):
                    val_n = get_num(i, n)
                    if val_n == mcs:
                        matches.append((i, n))
                        offsets_found[-1].add((i, n))

        results.append(matches)
    
    return results


def main():

    if len(sys.argv) < 2:
        print("Dump file path required as argument")
        exit(1)
    file_path = sys.argv[1]
    print(file_path)
    
    payloads, mcs_values = extract_mac_ul(file_path)
    
    results = find_mcs_bit_offset(payloads, mcs_values)

    print(total_cnt)
    print(mcs_present)

    # New code to count lengths with multiple MCS values
    multi_mcs_counts = {}
    for length, count in mcs_cnt:
        if length in multi_mcs_counts:
            if count in multi_mcs_counts[length]:
                multi_mcs_counts[length][count] += 1
            else:
                multi_mcs_counts[length][count] = 1
        else:
            multi_mcs_counts[length] = {}
            multi_mcs_counts[length][count] = 1

    # Print results in sorted order
    if multi_mcs_counts:
        print("\nLengths with corresponding number of MCS values:")
        for length in sorted(multi_mcs_counts.keys()):
            print(f"Length {length} bytes: {multi_mcs_counts[length]} packets")
    else:
        print("\nNo packets found with multiple MCS values")

    # # Plot probabilities
    # probabilities = {}
    # for key in total_cnt.keys():
    #     probabilities[key] = (0 if mcs_present.get(key) is None else mcs_present[key]) / total_cnt[key]
    # print(probabilities)
    #
    # keys = list(probabilities.keys())
    # values = list(probabilities.values())
    #
    # plt.figure(figsize=(10, 6))
    # plt.bar(keys, values, color='skyblue', edgecolor='black')
    # plt.xlabel('Length', fontsize=14)
    # plt.ylabel('Probability', fontsize=14)
    # plt.title('Probability of MCS Presence by Length', fontsize=16)
    # plt.xticks(keys, fontsize=12)
    # plt.yticks(fontsize=12)
    # plt.grid(axis='y', linestyle='--', alpha=0.7)
    # plt.tight_layout()
    # plt.show()

    # # Plot histogram
    # lengths = list(total_cnt.keys())
    # total_occurrences = list(total_cnt.values())
    # mcs_occurrences = [mcs_present.get(length, 0) for length in lengths]
    # bar_width = 2.4
    # plt.figure(figsize=(10, 6))
    # plt.bar([x - bar_width / 2 for x in lengths], total_occurrences, width=bar_width, label='Total Count', color='blue', align='center')
    # plt.bar([x + bar_width / 2 for x in lengths], mcs_occurrences, width=bar_width, label='MCS Present', color='orange', align='center')
    #
    # plt.xlabel('Length', fontsize=14)
    # plt.ylabel('Occurrences', fontsize=14)
    # plt.title('Histogram of Total Count and MCS Present by Length', fontsize=16)
    # plt.xticks(lengths, fontsize=12)
    # plt.legend(fontsize=12)
    # plt.grid(axis='y', linestyle='--', alpha=0.7)
    # plt.tight_layout()
    # plt.show()

    # # Find matches
    # first_matches = offsets_found[0]
    # print(f'{len(first_matches)} first matches found')
    #
    # common_matches = []
    # for match in first_matches:
    #     common = True
    #     for o in offsets_found:
    #         if match not in o:
    #             common = False
    #             break
    #     if common:
    #         common_matches.append(match)
    #
    # print(f'{len(common_matches)} matches found')
    # common_matches.sort()
    # print(common_matches)
    
    for idx, matches in enumerate(results):
        if not matches:
            print(f"\nPayload {idx+1} (MCS {mcs_values[idx]}):")
            print("  No matches found")

if __name__ == "__main__":
    main()
