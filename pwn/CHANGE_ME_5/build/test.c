#include <stdio.h>
#include <string.h>

// Function to print the flag
void secret() {
    printf("\n hd3{catching_the_news_upstairs}\n");
}

// Main game function where the buffer overflow occurs
void game() {
    char buffer[64]; // This is the vulnerable buffer
    printf("=======================================\n");
    printf("        GO WITH THE FLOW!             \n");
    printf("      ~ A Retro Adventure Game ~      \n");
    printf("=======================================\n");

    printf("Welcome to the Retro Adventure Game!\n");
    printf("Type your command: ");

    // Unsafe input function that allows for buffer overflow
    gets(buffer);

    printf("You entered: %s\n", buffer);
    printf("Keep playing...\n");
}

int main() {
    // Start the game
    game();

    // Control flow returns here unless overridden
    printf("Thanks for playing! No flag found!\n");
    return 0; // Normal exit
}
