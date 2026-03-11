import sys #터미널에서 입력한 값 가져오기
from pathlib import Path #파일 경로를 더 다루기 편하게 해줌

ELF_MAGIC = b"\x7fELF" #ELF 매직 넘버 저장


def is_elf_file(path):   #ELF 검사 함수
    target = Path(path)   #입력받은 경로를 파일 경로 객체로 바꿈

    if not target.exists(): #존재하지 않으면 거짓반환
        return False, "File does not exist."

    if not target.is_file(): #존재하는데 일반 파일이 아니면 거짓반환
        return False, "Target is not a file."

    try: #일단 해보고 에러생기면 예외로 처리
        with target.open("rb") as f: #바이너리 읽기 r=읽기, b=바이너리|with~as f 파일 안전하게 열고 닫는 문법
            magic = f.read(4) #불러온 파일 매직넘버 변수에 저장

        if magic == ELF_MAGIC: #매직넘버 확인
            return True, "Valid ELF magic number found."
        else:
            return False, "ELF magic number not found."

    except Exception as e: #에러 발생 시 e에 에러 내용을 담음.
        return False, f"Error while reading file: {e}" #거짓 반환 및 에러 서술


def analyze_target(path):   #검사함수 호출 > 결과 사용자에게 보여줌
    print(f"[ANALYZE] Target: {path}")

    is_elf, message = is_elf_file(path) #윗 함수 실행 후 값 받아옴

    if is_elf: #검사설명코드
        print("[RESULT] This file is an ELF binary.")
    else:
        print("[RESULT] This file is NOT an ELF binary.")

    print(f"[INFO] {message}") #가져온 보조설명 출력


def run_target(path):   #실행기능 넣을 자리, 지금은 비어있음.
    print(f"[RUN] Target: {path}")
    print("[INFO] Run feature is not implemented yet.")

#검사와 출력을 나누어 나중에 쓰기 좋게 해놓음.(웹UI 붙이기, JSON저장, 한번에 분석 등...)

def main(): #입력값을 확인하고 명령에 따라 적절한 함수로 보내는 중심 함수(분기)
    if len(sys.argv) < 3: #최소 3개의 문자열 필요 검사
        print("Usage:")
        print("  python main.py analyze <file>")
        print("  python main.py run <file>")
        return

    command = sys.argv[1]
    target = sys.argv[2]

    if command == "analyze":#분석할지 실행할지 고르는 분기
        analyze_target(target) #함수로 값을 주고 그 함수로 이동
    elif command == "run":
        run_target(target)
    else:
        print("Unknown command.")


if __name__ == "__main__": #이 파일을 직접 실행했을 때만 main()돌려라는 뜻
    main()