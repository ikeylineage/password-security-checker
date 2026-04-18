#include <stdio.h>
#include <string.h>
#include <math.h>
#include <termios.h>

// Password Security Checker
// Scores passwords out of 100 based on entropy, breach history and pattern detection
// Scoring: Entropy (33pts) + Dictionary (34pts) + Patterns (33pts) = 100pts
// compile: gcc main.c -o main -lm
//run: ./main
// requires: python3-requests (sudo apt install python3-requests)

int Entropy(int charPool, char password[50]) {
    return (strlen(password) * log2(charPool)); //calculates entropy based on the amount of bits in the password and the character pool
}

struct termios t;

int main(void) {
    tcgetattr(0, &t); //reads current terminal settings
    t.c_lflag &= ~ECHO; //disables echo
    t.c_lflag &= ~ICANON; // disables buffering
    tcsetattr(0, 0, &t); //applies current terminal settings

    int totalScore = 0;
    char password[50];
    int k = 0;

    printf("PASSWORD SECURITY CHECK\n");
    printf("type your password:\n");

    //replaces characters in the terminal with '*'

    while (k < 49) {
        char ch = getchar();
        
        if (ch == '\n') {
            break;
        }
        
        if (ch == 127) { //backspace on linux, replace with 8 if on windows
            if (k > 0) {
                k--;
                printf("\b \b"); //moves posistion back
            }
        } else{
            password[k] = ch;
            printf("*");
            k++;
        }
    }

    password[k] = '\0';
    printf("\n");

    t.c_lflag |= ECHO; //re enables echo
    tcsetattr(0, 0, &t);

    //ENTROPY SECURITY

    int entropyValue = Entropy(94, password); //calculates the entropy with most keyboard symbols (value = num of bits)
    int entropyScore = 0;

    int lowestValue = Entropy(26, password); //calculates entropy with only lower case letters

    double highestCase = pow(2, entropyValue) / 1000000000.0;
    double highestYears = highestCase / 31536000.0;

    double lowestCase = pow(2, lowestValue) / 1000000000.0;
    double lowestYears = lowestCase / 31536000.0;

    printf("\n");

    if (entropyValue >= 90) {
        entropyScore += 33;
    }
    else if (entropyValue >= 75) {
        entropyScore += 25;
    }
    else if (entropyValue >= 60) {
        entropyScore += 20;
    }
    else if (entropyValue >= 45) {
        entropyScore += 15;
    }
    else if (entropyValue >= 30) {
        entropyScore += 10;
    }
    else {
        entropyScore += 5;
    }

    //DICTIONARY SECURITY (see APICall.py)

    int dictionaryScore = 0;

    //uses an API call from "APICall.py" to access dictionary data from https://haveibeenpwned.com/

    char command[100];
    snprintf(command, sizeof(command), "python3 api-call.py %s", password);
    FILE *fp = popen(command, "r");

    int count;
    fscanf(fp, "%d", &count);
    pclose(fp);

    if (count == 0) {
        dictionaryScore += 34;
    }
    else if (count <= 10) {
        dictionaryScore += 20;
    }
    else if (count <= 100) {
        dictionaryScore += 10;
    }
    else if (count <= 1000) {
        dictionaryScore += 5;
    }

    //PATTERN SECURITY

    int patternScore = 0;

    //CHARACTER SUBSTITUTION

    char normalized[50]; //replaces password with a version that substitutes common char alternatives like @ -> a
    strcpy(normalized, password);

    char substitutions[] = {'@', '0', '$', '!'};
    char originals[]     = {'a', 'o', 's', 'i'};

    for (int i = 0; i < strlen(normalized); i++) {
        for (int j = 0; j < sizeof(substitutions); j++) {
            if (normalized[i] == substitutions[j]) {
                normalized[i] = originals[j];
            }
        }
    }

    //REPETITION CHECK

    int patternLength = 1;
    int maxRep = 1;

    //checks for repitition in the password, example: whaaaaatsup OUTPUT: patternLength = 5;
    for (int i = 1; i < strlen(normalized); i++) {
        char current = normalized[i];
        char previous = normalized[i - 1];

        if (current == previous) {
            patternLength++;
        } else {
            patternLength = 1;
        }

        if (patternLength > maxRep) {
            maxRep = patternLength;
        }
    }

    //SEQUENTIAL CHECK

    int increasing = 1;
    int decreasing = 1;
    int maxSeq = 1;

    //checks for increasing / decreasing patterns in numbers, example: 1234, Output: increasing = 4, example: 4321, Output: decreasing = 4
    for (int i = 1; i < strlen(normalized); i++) {
        char current = normalized[i];
        char previous = normalized[i - 1];

        if (current == previous + 1) {
            increasing++;
        } else {
            increasing = 1;
        }

        if (current == previous - 1) {
            decreasing++;
        }
        else {
            decreasing = 1;
        }

        int longest = increasing > decreasing ? increasing : decreasing;
        if (longest > maxSeq) maxSeq = longest;

    }

    if (maxSeq < 3) {
        patternScore += 20;
    }
    else if (maxSeq == 3) {
        patternScore += 10;
    }
    else if (maxSeq == 4) {
        patternScore += 5;
    }

    if (maxRep < 3) {
        patternScore += 13;
    }
    else if (maxRep == 3) {
        patternScore += 7;
    }
    else if (maxRep >= 4) {
        patternScore += 2;
    }

    totalScore = dictionaryScore + patternScore + entropyScore; //final score

    char *passwordRating;

    if (totalScore >= 90) {
        passwordRating = "very strong";
    }
    else if (totalScore >= 80) {
        passwordRating = "strong";
    }
    else if (totalScore >= 60) {
        passwordRating = "above average";
    }
    else if (totalScore >= 50) {
        passwordRating = "average";
    }
    else if (totalScore >= 30) {
        passwordRating = "weak";
    } else {
        passwordRating = "very weak";
    }

    //CONSOLE OUTPUT

    printf("Entropy score: %d\n\n", entropyScore);
    printf("Dictionary score: %d\n\n", dictionaryScore);
    printf("Pattern score = %d\n\n", patternScore);
    printf("Total score = %d/100\n\n", totalScore);

    printf("your password is %s\n\n", passwordRating);
    printf("lowest crack time: %.2f years \n\n", lowestYears);
    printf("highest crack time: %.2f years \n\n", highestYears);

    if (entropyScore < 20) {
        printf("your password is vulnerable to brute force attacks\n\n");
    }
    
    if (count > 0) {
        printf("your password has been breached %d times\n\n", count);
    }

    if (patternScore < 20) {
        printf("your password follows predictable patterns\n\n");
    }

    if (totalScore >= 80) {
    printf("your password looks good!\n\n");
    }

    printf("see https://www.troyhunt.com/tag/passwords/ for more info\n\n");
    
    return 0;
}