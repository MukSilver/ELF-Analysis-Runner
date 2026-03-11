#include <stdio.h>
#include <stdlib.h>

// argc: 전달된 인자의 개수, 입력 형식이 맞는지 검사할 때 사용
// argv: 전달된 인자들의 목록, 각 인자의 값을 꺼내 쓸 때 사용

int main(int argc, char *argv[]) { // argv 방식을 쓴 이유: CLI 테스트에 더 적합하다고 판단
    if (argc != 4) {               // scanf 방식은 C 기초 연습엔 직관적이지만, 이번 프로젝트 목적에는 argv가 더 잘 맞음
        printf("Usage: %s <num1> <operator> <num2>\n", argv[0]);
        printf("Example: %s 10 + 5\n", argv[0]);
        return 1;
    }

    double num1 = atof(argv[1]); // argv[1]은 첫 번째 숫자 문자열이고, atof로 실수형으로 변환한다.
    char op = argv[2][0];        // argv[2]에 저장된 연산자 문자열의 첫 번째 문자를 꺼내 op에 저장한다.
    double num2 = atof(argv[3]); // argv[3]은 두 번째 숫자 문자열이고, atof로 실수형으로 변환한다.
    double result;

    switch (op) {
        case '+':
            result = num1 + num2;
            break;
        case '-':
            result = num1 - num2;
            break;
        case '*':
            result = num1 * num2;
            break;
        case '/':
            if (num2 == 0) {
                printf("Error: division by zero\n");
                return 1;
            }
            result = num1 / num2;
            break;
        default:
            printf("Error: invalid operator '%c'\n", op);
            return 1;
    }

    printf("Result: %.2f\n", result);
    return 0;
}

/*
[실행 방법]
./samples/bin/calc 10 + 10
사칙연산 가능
*/