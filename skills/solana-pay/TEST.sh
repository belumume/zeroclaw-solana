# zeroclaw skill test cases — format: command | expected_exit | expected_output_pattern
# Reference generator emits one base58 line (32 random bytes encoded; 32-44 chars)
python3 scripts/gen_reference.py | 0 | [1-9A-HJ-NP-Za-km-z]{32,44}
# Two invocations never collide
python3 -c "import subprocess as s; a=s.check_output(['python3','scripts/gen_reference.py']); b=s.check_output(['python3','scripts/gen_reference.py']); print('UNIQUE' if a!=b else 'DUP')" | 0 | UNIQUE
# Decodes to exactly 32 bytes
python3 -c "import subprocess as s; A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; r=s.check_output(['python3','scripts/gen_reference.py']).decode().strip(); n=0; n=[n:=n*58+A.index(c) for c in r][-1]; raw=n.to_bytes((n.bit_length()+7)//8,'big'); raw=b'\x00'*(len(r)-len(r.lstrip('1')))+raw; print('LEN32' if len(raw)==32 else f'LEN{len(raw)}')" | 0 | LEN32
