#include <gc/gc.h>
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define malloc(n) GC_MALLOC(n)
#define calloc(m, n) GC_malloc((m) * (n))
#define strdup(a) GC_STRDUP(a)
#define strndup(a, b) GC_strndup(a, b)

#define MAGIC 0xbeefbead
#define MAX_SIZE 20

static int saved = 1;

typedef struct entry {
  char name[80];
  char contents[4096];
} entry;

typedef struct superblock {
  int magic;
  char name[80];
  int num_entries;
} superblock;

typedef struct block {
  int used;
  union {
    struct entry entry;
    struct superblock super;
  };
} block;

int get_magic(block *super) { return super->super.magic; }

int check_valid(block *journal) { return get_magic(journal) == MAGIC ? 1 : 0; }

void add_entry(block *dest, const char *title, const char *contents) {
  entry *res;
  res = calloc(1, sizeof(entry));
  int i = 1;
  while (dest[i].used) {
    i++;
  }
  printf("Adding entry at block %d.\n", i);
  strncpy(dest[i].entry.name, title, 80);
  strncpy(dest[i].entry.contents, contents, 4096);
  dest[i].used = 1;
  dest[0].super.num_entries++;
}

int get_entry_count(block *journal) { return journal[0].super.num_entries; }

#define plural(x) (x > 1 || x == 0)

void print_entries(block *journal, int with_contents) {
  int count = get_entry_count(journal);
  printf("There %s %d entr%s\n\n", plural(count) ? "are" : "is", count,
         plural(count) ? "ies" : "y");
  int i = 1, c = 1, found = journal[i].used;
  for (; i < MAX_SIZE && c <= count + 1; i++, c += (found = journal[i].used)) {
    if (found) {
      printf("Entry %d: "
             "%s\n============================================================="
             "===\n",
             c, journal[i].entry.name);
      if (with_contents) {
        printf("%s\n-----------------------------------------------------------"
               "-----\n\n",
               journal[i].entry.contents);
      }
    }
  }
}

void delete_entry(block *journal, int entry_number) {
  if (entry_number < 1) {
    return;
  }
  int count = get_entry_count(journal);
  int i = 1, c = 1, found = journal[i].used;
  for (; i < MAX_SIZE && c <= count; i++, c += (found = journal[i].used)) {
    if (c == entry_number) {
      break;
    }
  }
  journal[i].used = 0;
  journal[0].super.num_entries--;
}

block *alloc_journal(void) {
  block *res = calloc(MAX_SIZE, sizeof(block));
  res[0].used = 1;
  res[0].super.magic = MAGIC;
  return res;
}

block *create_new_journal(const char *name) {
  block *res = alloc_journal();
  superblock *super;
  super = calloc(1, sizeof(superblock));
  strncpy(super->name, name, 80);
  res[0].super = *super;
  return res;
}

block *read_journal(const char *filename) {
  block *res = alloc_journal();
  FILE *recover = fopen(filename, "rb");
  if (!recover) {
    return 0;
  }
  fread(res, sizeof(block), MAX_SIZE, recover);
  fclose(recover);
  return res;
}

void search_journal(block *journal, const char *term) {
  int count = get_entry_count(journal);
  int i = 1, c = 1, found = journal[i].used;
  for (; i < MAX_SIZE && c <= count + 1; i++, c += (found = journal[i].used)) {
    if (found && (strstr(journal[i].entry.name, term) ||
                  strstr(journal[i].entry.contents, term))) {
      printf("Entry %d: "
             "%s\n============================================================="
             "===\n%s\n--------------------------------------------------------"
             "--------\n\n",
             c, journal[i].entry.name, journal[i].entry.contents);
    }
  }
}

void write_journal(block *journal, const char *filename) {
  FILE *journal_file = fopen(filename, "wb");
  fwrite(journal, sizeof(block), MAX_SIZE, journal_file);
  fclose(journal_file);
}

void print_info(block *journal) {
  printf("Name: %s, Number of entries: %d\n", journal->super.name,
         journal->super.num_entries);
  printf("Journal is %svalid, magic number is 0x%x\n",
         (check_valid(journal) ? "" : "in"), get_magic(journal));
}

void change(block **p, block *someOtherAddress) { *p = someOtherAddress; }

// This is a macro to get input from the user with the prompt into the buffer x.
// If an EOF is received the program terminates.
#define getinput(x, prompt)                                                    \
  do {                                                                         \
    printf(prompt);                                                            \
    if (fgets(x, sizeof(x), stdin) == 0) {                                     \
      exit(0);                                                                 \
    }                                                                          \
    x[strlen(x) - 1] = '\0';                                                   \
  } while (x[0] == '\0')

#define CHUNK_SIZE 4096

static int encrypt_file(
    const char *target_file, const char *source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
  unsigned char buf_in[CHUNK_SIZE];
  unsigned char
      buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state st;
  FILE *fp_t, *fp_s;
  unsigned long long out_len;
  size_t rlen;
  int eof;
  unsigned char tag;
  fp_s = fopen(source_file, "rb");
  fp_t = fopen(target_file, "wb");
  crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
  fwrite(header, 1, sizeof header, fp_t);
  do {
    rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
    eof = feof(fp_s);
    tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
    crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in,
                                               rlen, NULL, 0, tag);
    fwrite(buf_out, 1, (size_t)out_len, fp_t);
  } while (!eof);
  fclose(fp_t);
  fclose(fp_s);
  return 0;
}

static int decrypt_file(
    const char *target_file, const char *source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
  unsigned char
      buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
  unsigned char buf_out[CHUNK_SIZE];
  unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
  crypto_secretstream_xchacha20poly1305_state st;
  FILE *fp_t, *fp_s;
  unsigned long long out_len;
  size_t rlen;
  int eof;
  int ret = -1;
  unsigned char tag;
  fp_s = fopen(source_file, "rb");
  fp_t = fopen(target_file, "wb");
  fread(header, 1, sizeof header, fp_s);
  if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
    goto ret; /* incomplete header */
  }
  do {
    rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
    eof = feof(fp_s);
    if (crypto_secretstream_xchacha20poly1305_pull(
            &st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) != 0) {
      goto ret; /* corrupted chunk */
    }
    if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
      goto ret; /* premature end (end of file reached before the end of the
                   stream) */
    }
    fwrite(buf_out, 1, (size_t)out_len, fp_t);
  } while (!eof);
  ret = 0;
ret:
  fclose(fp_t);
  fclose(fp_s);
  return ret;
}

void operate(block **journal, const char *input) {
  block *res = 0;
  int i = 0;
  while (input[i] == ' ') {
    i++;
  }
  char args[80] = {0};
  char contents[4096] = {0};
  unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
  if (strcmp(input, "load") == 0) {
    if (!saved) {
      getinput(args,
               "There is an unsaved journal in memory! Overwrite? [Y/n] ");
    }
    if (saved || args[0] == 'Y') {
      getinput(args, "Load journal from file: ");
      if (access(args, F_OK) != -1) {
        if (strstr(args, "_encrypted")) {
          const char *tmp_filename =
              strcat(strndup(args, strlen(args) - 10), ".tmp");
          strncpy((char *)key, getpass("Password: "), 32);

          int status = decrypt_file(tmp_filename, args, key);
          while (status == -1) {
            printf("Incorrect password!\n");
            strncpy((char *)key, getpass("Password: "), 32);
            status = decrypt_file(tmp_filename, args, key);
          }

          res = read_journal(tmp_filename);
          *journal = res;
          printf("File has loaded %ssuccessfully\n", res ? "" : "un");
          unlink(tmp_filename);
          saved = 1;
          return;
        }

      } else {
        printf("File not found!\n");
      }

    } else {
      printf("Operation cancelled.\n");
    }
  } else if (strcmp(input, "save") == 0) {
    getinput(args, "Save journal as: ");
    if (strstr(args, "_encrypted")) {
      const char *tmp_filename =
          strcat(strndup(args, strlen(args) - 10), ".tmp");
    ask_pass:
      strncpy((char *)key, getpass("Password: "), 32);
      if (strncmp((char *)key, getpass("Confirm password: "), 32) != 0) {
        printf("Passwords don't match!\n");
        goto ask_pass;
      }
      write_journal(*journal, tmp_filename);
      encrypt_file(args, tmp_filename, key);
      unlink(tmp_filename);
    } else {
      write_journal(*journal, args);
    }

    if (journal) {
      printf("Journal \"%s\" successfully saved to \"%s\".\n",
             (*journal)->super.name, args);
      saved = 1;
    } else {
      printf("There was an error saving to file.\n");
    }
  } else if (strcmp(input, "print") == 0) {
    print_entries(*journal, 1);
  } else if (strcmp(input, "append") == 0) {
    getinput(args, "Enter title of "
                   "entry\n===================================================="
                   "============\n");

    printf("\nEnter contents of "
           "entry\n------------------------------------------------------------"
           "----\n");
    int x = getchar(), j = 0;
    do {
      contents[j++] = x;
    } while ((x = getchar()) != '#');
    add_entry(*journal, args, contents);
    saved = 0;
  } else if (strcmp(input, "delete") == 0) {
    getinput(args, "Enter entry number: ");
    delete_entry(*journal, atoi(args));
    saved = 0;
  } else if (strcmp(input, "create") == 0) {
    res = alloc_journal();
    getinput(args, "New journal name: ");
    printf("Journal was %screated.\n", res ? "" : "not ");
    strncpy(res[0].super.name, args, 80);
    *journal = res;
    saved = 0;
  } else if (strcmp(input, "help") == 0) {
    printf("Available commands are "
           "[save/create/load/append/print/delete/help/info/format/search/"
           "list]\n");
  } else if (strcmp(input, "info") == 0) {
    print_info(*journal);
  } else if (strcmp(input, "format") == 0) {
    *journal = alloc_journal();
    saved = 0;
  } else if (strcmp(input, "search") == 0) {
    getinput(args, "Search term: ");
    search_journal(*journal, args);
  } else if (strcmp(input, "list") == 0) {
    print_entries(*journal, 0);
  }
}

int main(int argc, char const *argv[]) {
  if (sodium_init() == -1) {
    printf("Failed to initialize libsodium!\n");
    return 1;
  }

  GC_INIT();
  char tmp[80] = {0};
  block *result = alloc_journal();
  printf("Welcome to Ben's Journal, type \"help\" for a list of available "
         "commands.\n");
  for (;;) {
    if (!saved) {
      printf("(UNSAVED) ");
    }
    getinput(tmp, "> ");
    operate(&result, tmp);
  }
  return 0;
}
