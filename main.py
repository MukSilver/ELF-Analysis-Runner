import sys
import struct
from pathlib import Path

ELF_MAGIC = b"\x7fELF"

EI_CLASS = 4 #비트판단
EI_DATA = 5 #endian판단

ELFCLASS32 = 1 #값이1이면 32비트, 2면 64비트 ELF
ELFCLASS64 = 2

ELFDATA2LSB = 1 #값이 1이면 리틀엔디언, 2면 빅엔디언
ELFDATA2MSB = 2

PT_DYNAMIC = 2 #동적 링크 관련 정보가 들어 있는 구역
PT_INTERP = 3 #인터프리터 경로가 들어 있는 구역

PT_GNU_STACK = 0x6474e551 #스택 실행권한 헤더
PF_X = 0x1 #실행권한 비트

ET_EXEC = 2 #일반 실행 파일
ET_DYN = 3 # 공유 라이브러리 타입/ PIE 실행 파일도 이 값으로 보임

PT_GNU_RELRO = 0x6474e552  # RELRO 세그먼트

DT_NULL = 0
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6ffffffb

DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

def make_result(path): #분석결과 저장할 기본 딕셔너리를 만드는 함수
    return {
        "file_path": str(path),
        "is_elf": False,
        "arch": None, 
        "is_dynamic": None,
        "interpreter": None,
        "nx": None,
        "pie": None,
        "relro": None,
        "canary": None,
        "notes": [],
    }


def validate_target(path): #경로 검증 함수
    target = Path(path)

    if not target.exists():#파일이나 폴더 없으면 거짓반환
        return False, "File does not exist."

    if not target.is_file():#일반파일아니면 거짓반환
        return False, "Target is not a file."

    return True, "Target is valid."


def get_endian_prefix(ei_data): #endian 판별 함수
    if ei_data == ELFDATA2LSB:
        return "<"   # little endian
    if ei_data == ELFDATA2MSB:
        return ">"   # big endian
    return None #둘다아니면, 상위함수에서 오류 처리할 수 있게 none 반환

#f = 이미 열러있는 파일 객체 / elf_class = 32비트or64비트 / 엔디언판단/시작위치/하나의크기/개수
def read_program_headers(f, elf_class, endian_prefix, e_phoff, e_phentsize, e_phnum):
    headers = []#읽은 헤더들을 저장할 리스트
#Program Header가 파일 어디에 몇 개 있고, 각각 어떻게 읽어야 하는지를 받아서 읽는 함수
    if e_phoff == 0 or e_phnum == 0:
        return headers
    #헤더 없으면 그냥 반환

    if elf_class == ELFCLASS32:
        fmt = endian_prefix + "IIIIIIII"
        expected_size = struct.calcsize(fmt)#바이트계산
        #32비트일 때 헤더 해석할 구조를 만든 것

        for i in range(e_phnum):#헤더 하나씩 읽는 루프
            offset = e_phoff + (i * e_phentsize) #각 헤더 파일 시작점
            f.seek(offset) #포인터를 그 위치로 이동
            data = f.read(expected_size)#해당위치에서의 헤더 하나 읽기

            if len(data) != expected_size:#바이트 수 부족하면 이상한파일이고, 예외 발생시켜 상위 함수에서 처리
                raise ValueError("Failed to read ELF32 program header.")

            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack(fmt, data)
                    #읽은 바이트를 헤더 형식에 맞게 분해한다.
            headers.append({
                "p_type": p_type,
                "p_offset": p_offset,
                "p_filesz": p_filesz,
                "p_flags": p_flags,
            })#분석에 필요한 값들만 추려서 저장 하겠다는 것.

    elif elf_class == ELFCLASS64: #64일때
        fmt = endian_prefix + "IIQQQQQQ" #헤더구조를 읽기 위한 포맷, 32비트와는 구조 배치가 조금 다르다.
        expected_size = struct.calcsize(fmt)#읽기위한 바이트 수 계산.

        for i in range(e_phnum):#위와 같음
            offset = e_phoff + (i * e_phentsize)
            f.seek(offset)
            data = f.read(expected_size)

            if len(data) != expected_size:
                raise ValueError("Failed to read ELF64 program header.")

            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(fmt, data)

            headers.append({
                "p_type": p_type,
                "p_offset": p_offset,
                "p_filesz": p_filesz,
                "p_flags": p_flags,
            })

    else: #둘다 아니면 예외 처리
        raise ValueError("Unsupported ELF class.")
#읽어온 간추린 헤더목록 반환
    return headers

def read_dynamic_entries(f, elf_class, endian_prefix, program_headers):
    dynamic_header = next((ph for ph in program_headers if ph["p_type"] == PT_DYNAMIC), None)

    if dynamic_header is None:
        return []

    f.seek(dynamic_header["p_offset"])
    dynamic_data = f.read(dynamic_header["p_filesz"])

    if elf_class == ELFCLASS32:
        fmt = endian_prefix + "II"
    elif elf_class == ELFCLASS64:
        fmt = endian_prefix + "QQ"
    else:
        raise ValueError("Unsupported ELF class for dynamic section.")

    entry_size = struct.calcsize(fmt)
    entries = []

    for i in range(0, len(dynamic_data), entry_size):
        chunk = dynamic_data[i:i + entry_size]

        if len(chunk) != entry_size:
            break

        d_tag, d_val = struct.unpack(fmt, chunk)
        entries.append({
            "d_tag": d_tag,
            "d_val": d_val,
        })

        if d_tag == DT_NULL:
            break

    return entries

def analyze_file(path):#분석 함수
    result = make_result(path)
    ok, message = validate_target(path)

    if not ok:
        result["notes"].append(message)
        return result

    target = Path(path)

    try:
        with target.open("rb") as f:#with를 쓰면 끝나고 자동으로 닫힘
            ident = f.read(16)

            if len(ident) < 16: #이거보다 작으면 ELF 아님
                result["notes"].append("File is too short to be a valid ELF.")
                return result

            if ident[:4] != ELF_MAGIC:#매직넘버로 ELF 판별
                result["notes"].append("ELF magic number not found.")
                return result

            result["is_elf"] = True#결과값에 true 기록

            elf_class = ident[EI_CLASS]
            ei_data = ident[EI_DATA]

            if elf_class == ELFCLASS32:#비트에 따른 포맷형식
                result["arch"] = "ELF32"
                ehdr_fmt = "HHIIIIIHHHHHH"
            elif elf_class == ELFCLASS64:
                result["arch"] = "ELF64"
                ehdr_fmt = "HHIQQQIHHHHHH"
            else:
                result["notes"].append("Unsupported ELF class.")
                return result

            endian_prefix = get_endian_prefix(ei_data)
            if endian_prefix is None:#엔디언 값을 보고 < 또는 > 얻기
                result["notes"].append("Unsupported ELF endianness.")
                return result

            ehdr_size = struct.calcsize(endian_prefix + ehdr_fmt) #헤더 읽기
            ehdr_data = f.read(ehdr_size)#그다음 본문읽기

            if len(ehdr_data) != ehdr_size:#헤더 끝까지 못읽었으면 실패로 처리
                result["notes"].append("Failed to read ELF header.")
                return result

            ehdr = struct.unpack(endian_prefix + ehdr_fmt, ehdr_data)#읽은 헤더 바이트를 실제 필드 값들로 해석

            e_type = ehdr[0] #PIE 판별용 ELF 타입 추출
        
            if e_type == ET_DYN:
                result["pie"] = True
            elif e_type == ET_EXEC:
                result["pie"] = False
            else:
                result["pie"] = None
                result["notes"].append(f"Unknown ELF type for PIE check: {e_type}")

            # e_phoff, e_phentsize, e_phnum 일부러 중요한 값 3개만 뽑아온것.
            e_phoff = ehdr[4]
            e_phentsize = ehdr[8]
            e_phnum = ehdr[9]

            program_headers = read_program_headers( #해더목록 받아옴.
                f,
                elf_class,
                endian_prefix,
                e_phoff,
                e_phentsize,
                e_phnum
            )

            dynamic_entries = read_dynamic_entries(
                f,
                elf_class,
                endian_prefix,
                program_headers
            )

            result["is_dynamic"] = any(ph["p_type"] == PT_DYNAMIC for ph in program_headers) #PT_DYNAMIC 있으면 동적 링크

            interp_header = next((ph for ph in program_headers if ph["p_type"] == PT_INTERP), None)
#인터프리터 추출
            if interp_header is not None:
                f.seek(interp_header["p_offset"])
                interp_data = f.read(interp_header["p_filesz"])
                result["interpreter"] = interp_data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")#문장열 끝표시 제거, 실제 경로 문자열 부분 가져오기, 바이트를 사람이 읽는 문자열로 변환
            else:#"/lib64/ld-linux-x86-64.so.2"이런 값이 저장됨
                result["interpreter"] = None#인터프리터가 없고 정적 링크 바이너리일 수 있음

            gnu_stack = next((ph for ph in program_headers if ph["p_type"] == PT_GNU_STACK), None) #NX판별용 PT GNU STACK 찾는것

            if gnu_stack is None:
                result["nx"] = None
                result["notes"].append("PT_GNU_STACK not found.")
            else:
                if gnu_stack["p_flags"] & PF_X:
                    result["nx"] = False
                else:
                    result["nx"] = True

            has_gnu_relro = any(ph["p_type"] == PT_GNU_RELRO for ph in program_headers)

            has_bind_now = any(
                entry["d_tag"] == DT_BIND_NOW or
                (entry["d_tag"] == DT_FLAGS and (entry["d_val"] & DF_BIND_NOW)) or
                (entry["d_tag"] == DT_FLAGS_1 and (entry["d_val"] & DF_1_NOW))
                for entry in dynamic_entries
            )

            if has_gnu_relro and has_bind_now:
                result["relro"] = "full"
            elif has_gnu_relro:
                result["relro"] = "partial"
            else:
                result["relro"] = "none"

            f.seek(0)
            file_data = f.read()

            if b"__stack_chk_fail" in file_data or b"__stack_chk_guard" in file_data:
                result["canary"] = True
            else:
                result["canary"] = False

            result["notes"].append("Basic ELF analysis completed.")
            return result #여기까지오면 성공 반환

    except Exception as e:
        result["notes"].append(f"Error while analyzing file: {e}")
        return result#실패하면 오류 내용 넣고 반환 실패조차도 결과로 남기겠다는 것


def print_analysis_result(result): #분석 결과 딕셔너리를 보기좋게 출력하는 함수
    print(f"[ANALYZE] Target: {result['file_path']}") #어떤 파일 분석했는지 출력
    print(f"[RESULT] is_elf       : {result['is_elf']}")
    print(f"[RESULT] arch         : {result['arch']}")
    print(f"[RESULT] is_dynamic   : {result['is_dynamic']}")
    print(f"[RESULT] interpreter  : {result['interpreter']}")
    print(f"[RESULT] nx           : {result['nx']}")
    print(f"[RESULT] pie          : {result['pie']}")
    print(f"[RESULT] relro        : {result['relro']}")
    print(f"[RESULT] canary       : {result['canary']}")

    if result["notes"]:#노트가 하나라도 있으면 한줄씩 출력.
        for note in result["notes"]:
            print(f"[NOTE] {note}")


def analyze_target(path):
    result = analyze_file(path)
    print_analysis_result(result)


def run_target(path):
    print(f"[RUN] Target: {path}")
    print("[INFO] Run feature is not implemented yet.")


def main():
    if len(sys.argv) < 3: #최소 3개 이상 보는 구조임
        print("Usage:")
        print("  python main.py analyze <file>")
        print("  python main.py run <file>")
        return

    command = sys.argv[1] #첫인자는 명령어
    target = sys.argv[2] #두번째 인자는 파일경로

    if command == "analyze": #분석과 런의 분기
        analyze_target(target)
    elif command == "run":
        run_target(target)
    else:
        print("Unknown command.")


if __name__ == "__main__": #직접 실행여부 확인
    main()

    #struct.unpack()은
    #바이트를 의미있는 필드로 변환해준다. 중요함.

    #e_ident와 ELF 헤더는 다름
    #e_ident는 맨 앞 16바이트
    #ELF 헤더는 그 뒤에 이어지는 구조체
    #그래서 코드는 16바이트 읽고 헤더 본문을 읽음.

    #프로그램 헤더는 실행관점보단,
    #DYNAMIC, INTERP 즉, 이 ELF가
    #동적링크인지,
    #어떤 로더를 쓰는지
    #같은 실행 관련 정보를 봐야함.

    #ehdr_fmt = "HHIIIIIHHHHHH"   # ELF32
    #ehdr_fmt = "HHIQQQIHHHHHH"   # ELF64
    #ELF헤더의 C구조체를 그대로 옮긴 것
    #"<HHIQQQIHHHHHH"
    #little endian으로
    #2, 2, 4, 8, 8, 8, 4, 2, 2, 2, 2, 2, 2 바이트씩 잘라 읽어라라는 거임.
    #C구조체가 64비트는 저렇게 되어있기에 저렇게 한거고 ㅇㅇ
    #ELF 규격 문서에 정의된 구조체의 필드 순서 + 각 필드의 바이트 크기
    #를  struct.unpack() 문법으로 옮긴것이다...



    #상수들
#↓
#read_program_headers()
#↓
#read_dynamic_entries()   ← 새로 추가
#↓
#analyze_file()
    #├─ ELF 읽기
    #├─ PIE 판별
    #├─ program_headers 읽기
    #├─ dynamic_entries 읽기   ← 새로 추가
    #├─ is_dynamic
    #├─ interpreter
    #├─ NX
    #├─ RELRO   ← 새로 추가
    #├─ Canary  ← 새로 추가
    #└─ return