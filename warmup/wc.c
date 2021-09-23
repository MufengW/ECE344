#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include "common.h"
#include "wc.h"

long map_size = 0;
typedef struct hashMap {
    int count;
    char *word;
} hash_map;

struct wc {
    /* you can define this struct to have whatever fields you want. */
    hash_map **map;
};

void build_map();

unsigned long get_key();

void insert();

struct wc *
wc_init(char *word_array, long size) {
    struct wc *wc = (struct wc *) malloc(sizeof(struct wc));
    memset(wc, 0, sizeof(struct wc));

    assert(wc);

    map_size = size;

    wc->map = malloc(sizeof(hash_map *) * map_size);
    memset(wc->map, 0, sizeof(hash_map *) * map_size);
    assert(wc->map);

    build_map(word_array, size, wc);
    return wc;
}

void
wc_output(struct wc *wc) {
    for (int i = 0; i < map_size; i++) {
        if (wc->map[i]) {
            printf("%s:%d\n", wc->map[i]->word, wc->map[i]->count);
        }
    }
}

void
wc_destroy(struct wc *wc) {
    for (int i = 0; i < map_size; ++i) {
        if (wc->map[i]) {
            free(wc->map[i]->word);
            free(wc->map[i]);
        }
    }
    free(wc->map);
    free(wc);
}

void build_map(char *word_array, long size, struct wc *wc) {
	char *tmp_cpy = strdup(word_array);
	char delim[] = " \n\t\v\f\r";
	char * word = strtok(tmp_cpy,delim);
	while(word!=NULL){
			unsigned long hash_key = get_key(word);
			int hash_idx = hash_key % map_size;
			if(wc->map[hash_idx]==NULL) {
				wc->map[hash_idx] = (struct hashMap *) malloc(sizeof(struct hashMap));
				memset(wc->map[hash_idx], 0, sizeof(struct hashMap));
				insert(word,wc->map[hash_idx]);

			} else {
				bool found = false;
				while (wc->map[hash_idx] != NULL) {
					if(strcmp(wc->map[hash_idx]->word, word)==0) {
						++(wc->map[hash_idx]->count);
						found = true;
						break;
					} else {
						hash_idx = (hash_idx + 1) % map_size;
					}
				}
				if(!found) {
					wc->map[hash_idx] = (struct hashMap*) malloc(sizeof(struct hashMap));
					memset(wc->map[hash_idx], 0, sizeof(struct hashMap));
					insert(word,wc->map[hash_idx]);
				}
			}
			word = strtok(NULL,delim);

		}
}

unsigned long get_key(char *word) {
    unsigned long hash = 5381;
    int c;

    while ((int) (c = *word++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

void insert(char *word, hash_map *tmp_map) {
    tmp_map->count = 1;
    tmp_map->word = malloc(strlen(word) + 1);
    memset(tmp_map->word, 0, strlen(word) + 1);
    strcpy(tmp_map->word, word);
}
