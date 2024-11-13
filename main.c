//2020113437 taewon park
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <pwd.h>
#include <ncurses.h>
#include <signal.h>

typedef struct Process
{
    int pid;              // PID: 프로세스 식별자
    char user[32];        // USER: 프로세스의 소유자
    int pr;               // PR: 프로세스의 우선 순위
    int ni;               // NI: nice 값
    unsigned long virt;   // VIRT: 가상 메모리 양 (단위: kb)
    unsigned long res;    // RES: 물리 RAM 양 (단위: kb)
    unsigned long shr;    // SHR: 공유 메모리 양
    char state;           // S: 프로세스의 현재 상태
    unsigned long utime;  // 사용자 모드에서 소모한 CPU 시간
    unsigned long stime;  // 커널 모드에서 소모한 CPU 시간
    unsigned long time;   // 총 CPU 시간
    float cpu_percent;    // %CPU: CPU 사용률
    float mem_percent;    // %MEM: 메모리 사용률
    char command[256];    // COMMAND: 실행 명령
    struct Process *next; // 형제 프로세스 연결
} Process;

float total_cpu_time; // 전체 CPU 시간
float total_mem;      // 전체 RAM
Process *processes;   // 전역 변수로 프로세스 목록

// 숫자를 적절한 단위로 변환하는 함수
const char *formatSize(unsigned long size)
{
    static char buffer[20];
    if (size >= 1024 * 1024 * 1024)
    {
        snprintf(buffer, sizeof(buffer), "%.2fG", size / (1024.0 * 1024 * 1024));
    }
    else if (size >= 1024 * 1024)
    {
        snprintf(buffer, sizeof(buffer), "%.2fM", size / (1024.0 * 1024));
    }
    else if (size >= 1024)
    {
        snprintf(buffer, sizeof(buffer), "%.2fK", size / 1024.0);
    }
    else
    {
        snprintf(buffer, sizeof(buffer), "%luB", size);
    }
    return buffer;
}

// 전체 CPU 시간 가져오기
void get_total_cpu_time()
{
    FILE *file = fopen("/proc/stat", "r");
    if (file)
    {
        char line[256];
        fgets(line, sizeof(line), file);
        unsigned long user, nice, system, idle, iowait, irq, softirq, steal;
        sscanf(line, "cpu %lu %lu %lu %lu %lu %lu %lu %lu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal);
        total_cpu_time = user + nice + system + idle + iowait + irq + softirq + steal;
        fclose(file);
    }
    else
    {
        perror("Unable to open /proc/stat");
    }
}

// 전체 메모리 크기 가져오기
void get_total_memory()
{
    FILE *file = fopen("/proc/meminfo", "r");
    if (file)
    {
        char line[256];
        while (fgets(line, sizeof(line), file))
        {
            if (sscanf(line, "MemTotal: %f kB", &total_mem) == 1)
            {
                total_mem /= 1024; // MB 단위로 변환
                break;
            }
        }
        fclose(file);
    }
    else
    {
        perror("Unable to open /proc/meminfo");
    }
}
// 프로세스 정보를 읽어오는 함수
// 프로세스 정보를 읽어오는 함수
Process *read_processes(int *total_processes)
{
    DIR *proc_dir = opendir("/proc");
    struct dirent *entry;
    Process *head = NULL, *tail = NULL;
    *total_processes = 0;

    while ((entry = readdir(proc_dir)) != NULL)
    {
        if (isdigit(entry->d_name[0]))
        {
            int pid = atoi(entry->d_name);
            char path[512];
            snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
            FILE *file1 = fopen(path, "r");
            snprintf(path, sizeof(path), "/proc/%s/status", entry->d_name);
            FILE *file2 = fopen(path, "r");

            if (file1 && file2)
            {
                Process *p = malloc(sizeof(Process));
                unsigned long utime, stime;
                fscanf(file1, "%d %*s %*c %d %lu %*d %*d %*d %*d %*d %*d %lu %*s %*u %*u %*u %*u %*u %*u %*u",
                       &p->pid, &p->pr, &utime, &stime);
                p->utime = utime;
                p->stime = stime;
                p->time = utime + stime;

                fseek(file1, 0, SEEK_SET);
                fscanf(file1, "%*d %*s %c", &p->state);
                p->next = NULL;

                // UID 및 상태 확인
                unsigned int uid = 0;
                char line[256];
                while (fgets(line, sizeof(line), file2))
                {
                    if (sscanf(line, "Uid:\t%u", &uid) == 1)
                        break;
                }

                // 커널 스레드 확인: 상태가 'S' 또는 'R'이고 UID가 0인 경우
                if ((p->state == 'S' || p->state == 'R') && uid == 0)
                {
                    free(p); // 커널 스레드인 경우 메모리 해제
                    fclose(file1);
                    fclose(file2);
                    continue; // 다음 프로세스로 넘어감
                }

                struct passwd *pw = getpwuid(uid);
                if (pw)
                {
                    strncpy(p->user, pw->pw_name, sizeof(p->user) - 1);
                    p->user[sizeof(p->user) - 1] = '\0';
                }
                else
                {
                    strncpy(p->user, "unknown", sizeof(p->user) - 1);
                    p->user[sizeof(p->user) - 1] = '\0';
                }

                // 메모리 정보 읽기
                while (fgets(line, sizeof(line), file2))
                {
                    if (sscanf(line, "VmSize:\t%lu kB", &p->virt) == 1)
                        continue;
                    if (sscanf(line, "VmRSS:\t%lu kB", &p->res) == 1)
                        continue;
                    if (sscanf(line, "VmShared:\t%lu kB", &p->shr) == 1)
                        continue;
                }

                snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
                FILE *cmd_file = fopen(path, "r");
                if (cmd_file)
                {
                    fgets(p->command, sizeof(p->command), cmd_file);
                    fclose(cmd_file);
                }
                else
                {
                    strncpy(p->command, "unknown", sizeof(p->command) - 1);
                    p->command[sizeof(p->command) - 1] = '\0';
                }

                // 프로세스 목록에 추가
                if (!head)
                {
                    head = p;
                    tail = p;
                }
                else
                {
                    tail->next = p;
                    tail = p;
                }

                (*total_processes)++;
                fclose(file1);
                fclose(file2);
            }
        }
    }
    closedir(proc_dir);
    return head;
}

// 메모리 해제 함수
void free_processes(Process *processes)
{
    while (processes)
    {
        Process *temp = processes;
        processes = processes->next;
        free(temp);
    }
}

// CPU 사용률 계산 함수
float calculate_cpu_usage(Process *p)
{
    return (float)(p->utime + p->stime) / total_cpu_time * 100;
}

// 메모리 사용률 계산
float calculate_mem_usage(Process *p)
{
    return (float)p->res / total_mem * 100;
}

// 터미널 크기 변경 시 재조정 함수
void resize_handler(int signum)
{
    // 화면을 지우고, 새로운 헤더를 출력합니다.
    clear();
    printw(" PID  | User      |   PR   |   NI   |   VIRT   |   RES    |   SHR    | State |  %%CPU  |  %%MEM  |  TIME+   | COMMAND\n");
    printw("----------------------------------------------------------------------------------------------------\n");

    // 프로세스 정보를 다시 출력합니다.
    Process *p = processes; // 전역 변수로 프로세스 목록을 접근
    while (p != NULL)
    {
        printw("%5d | %-10s | %6d | %6d | %10s | %10s | %10s | %c    | %6.2f%% | %6.2f%% | %8lu | %-20s\n",
               p->pid, p->user, p->pr, p->ni,
               formatSize(p->virt), formatSize(p->res), formatSize(p->shr),
               p->state, p->cpu_percent, p->mem_percent, p->time, p->command);
        p = p->next;
    }

    refresh(); // 화면 업데이트
}

// 메인 함수
int main()
{
    // ncurses 초기화
    // ncurses 초기화
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);

    // SIGWINCH 시그널 핸들러 등록
    signal(SIGWINCH, resize_handler);

    // 전체 CPU 시간과 메모리 크기 가져오기
    get_total_cpu_time();
    get_total_memory();

    int total_processes = 0;
    processes = read_processes(&total_processes);

    // 각 프로세스의 CPU 및 메모리 사용률 계산
    Process *p = processes;
    while (p)
    {
        p->cpu_percent = calculate_cpu_usage(p);
        p->mem_percent = calculate_mem_usage(p);
        p = p->next;
    }

    // 스크롤 관련 변수
    int start_line = 0;                    // 현재 스크롤 위치
    int max_lines = LINES - 4;             // 화면에 표시할 최대 프로세스 수
    int displayed_lines = total_processes; // 실제로 출력된 프로세스 수
    int scroll_offset = 0;                 // 오른쪽 스크롤 오프셋

    // 결과 출력 루프
    while (1)
    {
        clear();
        printw(" PID  | User      |   PR   |   NI   |   VIRT   |   RES    |   SHR    | State |  %%CPU  |  %%MEM  |  TIME+   | COMMAND\n");
        printw("----------------------------------------------------------------------------------------------------\n");

        // 프로세스 정보 출력
        p = processes;
        int line_count = 0;
        while (p != NULL)
        {
            if (line_count >= start_line && line_count < start_line + max_lines)
            {
                // 오른쪽으로 스크롤된 부분을 출력
                printw("%5d | %-10s | %6d | %6d | %10s | %10s | %10s | %c    | %6.2f%% | %6.2f%% | %8lu | %-20s\n",
                       p->pid, p->user, p->pr, p->ni,
                       formatSize(p->virt), formatSize(p->res), formatSize(p->shr),
                       p->state, p->cpu_percent, p->mem_percent, p->time, p->command + scroll_offset);
            }
            p = p->next;
            line_count++;
        }

        refresh(); // 화면 업데이트

        int ch = getch(); // 사용자 입력 대기
        if (ch == KEY_UP && start_line > 0)
        {
            start_line--; // 위로 스크롤
        }
        else if (ch == KEY_DOWN && start_line < displayed_lines - max_lines)
        {
            start_line++; // 아래로 스크롤
        }
        else if (ch == KEY_RIGHT)
        {
            scroll_offset += 1; // 오른쪽으로 스크롤
        }
        else if (ch == KEY_LEFT)
        {
            if (scroll_offset > 0)
            {
                scroll_offset -= 1; // 왼쪽으로 스크롤
            }
        }
        else if (ch == 'q')
        {
            break; // 'q'를 누르면 종료
        }
    }

    free_processes(processes); // 메모리 해제
    endwin();                  // ncurses 종료
    return 0;
}