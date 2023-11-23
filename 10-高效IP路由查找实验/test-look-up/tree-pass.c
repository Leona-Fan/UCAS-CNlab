#include "tree.h"
#include <stdio.h>
#include <stdlib.h>

TrieNode *trie;
SuperTrieNode *superTrie;


// Convert the ip to uint32_t
static inline uint32_t convert_ip_to_uint(char *cip) {
    unsigned int a, b, c, d;
    sscanf(cip, "%u.%u.%u.%u", &a, &b, &c, &d);
    uint32_t res = (a << 24) | (b << 16) | (c << 8) | d;
    return res;
}   



// Get the bits from start to end (inclusive)
static inline uint32_t get_bit(uint32_t uip, int pos) {
    uint32_t res = (uip & (1 << pos))? 1 : 0;
    return res;
}

// Get the prefix from an unsigned int (inclusive)
static inline uint32_t get_prefix(uint32_t uip, int prefix) {
    uint32_t mask = (uint32_t)(~(0xFFFFFFFF >> prefix));
    return uip & mask;
}

// return an array of ip represented by an unsigned integer, size is TEST_SIZE
uint32_t* read_test_data(const char* lookup_file) {
    FILE *fp = fopen(lookup_file, "r");
    uint32_t *res = (uint32_t*)malloc(sizeof(uint32_t)*(TEST_SIZE+10));

    int cnt = 0;
    while (!feof(fp)) {
        char sip[30];
        fscanf(fp, "%s", sip);
        res[cnt++] = convert_ip_to_uint(sip);
    }
    return res;
}

// Init a Trie tree
TrieNode* trie_init() {
    TrieNode *root = (TrieNode*)malloc(sizeof(TrieNode));
    root -> ip = 0;
    root -> port = 0;
    root -> prefix = 0;
    root -> has = 0;

    root -> children[0] = root -> children[1] = NULL;
    return root;
}

// Insert a node in Trie tree
void insert_node(TrieNode *root, uint32_t ip, int port, int prefix) {
    TrieNode *cur_node = root, *next;
    int cur_bit;
    while (cur_node && cur_node -> prefix < prefix) {
        cur_bit = get_bit(ip, 31 - cur_node -> prefix);
        next = cur_node -> children[cur_bit];
        // If the children node's space has not been allocated.
        if (next == NULL) {
            next = (TrieNode*)malloc(sizeof(TrieNode));
            next -> ip = get_prefix(ip, cur_node -> prefix + 1);
            next -> port = 0;
            next -> prefix = cur_node -> prefix + 1;
            next -> has = 0;
            next -> children[0] = next -> children[1] = NULL;
            
            cur_node -> children[cur_bit] = next;
        }
        cur_node = next;
    }

    if (cur_node != NULL) {
        cur_node -> port = port;
        cur_node -> has = 1;
    }
}

uint32_t find_ip(TrieNode *root, uint32_t ip) {
    TrieNode *match = NULL;
    TrieNode *cur = root;

    while(cur) {
        if (cur -> has && cur -> ip == get_prefix(ip, cur -> prefix)) {
            match = cur;
        }
        cur = cur -> children[get_bit(ip, 31 - cur -> prefix)];
    }

    return match? match -> port : -1;
}

// Constructing a trie-tree to lookup according to `forward_file`
void create_tree(const char* forward_file) {
    FILE *fp = fopen(forward_file, "r");
    if (fp == NULL) {
        perror("Open source file fails");
        exit(1);
    }

    trie = trie_init();
    char sip[30];
    int prefix, port_num;

    while (!feof(fp)) {
        fscanf(fp, "%s %d %d", sip, &prefix, &port_num);
        uint32_t uip = convert_ip_to_uint(sip);
        insert_node(trie, uip, port_num, prefix);
    }
}


// Look up the ports of ip in file `lookup_file` using the basic tree
uint32_t *lookup_tree(uint32_t* ip_vec) {
    uint32_t *res = (uint32_t*)malloc((TEST_SIZE+1)*sizeof(uint32_t));
    for (int i = 0; i < TEST_SIZE; i++) {
        uint32_t ip = ip_vec[i];
        res[i] = find_ip(trie, ip);
    }
    return res;
}

// Init a super root
SuperTrieNode* superTrie_init() {
    SuperTrieNode *superTrie = (SuperTrieNode*)malloc(sizeof(SuperTrieNode));
    for (int i = 0; i < BRANCH; i++) {
        superTrie -> children[i] = (TrieNodeadv*)malloc(sizeof(TrieNodeadv));
        superTrie -> children[i] -> prefix = PREFIX_LEN;
        superTrie -> children[i] -> ip = i << PREFIX_LEN;
        superTrie -> children[i] -> has = 0;
        superTrie -> children[i] -> port = 0;
        superTrie -> children[i] -> is_odd = 0;
        superTrie -> children[i] -> compress = 4;
        for (int j = 0; j < 4; j++) {
            superTrie -> children[i] -> children[j] = NULL;
        }
    }
    return superTrie;
}

// branch the tree into 2 bit
void branch_tree(TrieNodeadv *root, uint32_t ip, int port, int prefix) {
    TrieNodeadv *cur_node = root, *next;
    int ori_prefix = root -> prefix;
    cur_node -> prefix = PREFIX_LEN;
    int cur_bit1, cur_bit2;
    while (cur_node && cur_node -> prefix < prefix - 1) {
        cur_bit1 = get_bit(ip, 31 - cur_node -> prefix);
        cur_bit2 = get_bit(ip, 30 - cur_node -> prefix);
        next = cur_node -> children[(cur_bit1 << 1) | cur_bit2];
        // If the children node's space has not been allocated.
        if (next == NULL) {
            next = (TrieNodeadv*)malloc(sizeof(TrieNodeadv));
            next -> ip = get_prefix(ip, cur_node -> prefix + 2);
            next -> port = 0;
            next -> prefix = cur_node -> prefix + 2;
            next -> has = 0;
            next -> children[0] = next -> children[1] = NULL;
            next -> children[2] = next -> children[3] = NULL;
            next -> is_odd = 0;
            next -> compress = 4;
            cur_node -> children[(cur_bit1 << 1) | cur_bit2] = next;
            cur_node -> compress = cur_node -> compress -1;
        }
        else if(next -> is_odd == 1 && next -> prefix == prefix){
            next -> ip = get_prefix(ip, cur_node -> prefix + 2);
            next -> is_odd = 0;
        }
        cur_node = next;
    }

    if (cur_node -> prefix == prefix - 1) {
        TrieNodeadv *next1, *next2;
        cur_bit1 = get_bit(ip, 31 - cur_node -> prefix);
        next1 = cur_node -> children[cur_bit1 << 1];
        if (next1 == NULL) {
            next1 = (TrieNodeadv*)malloc(sizeof(TrieNodeadv));
            next1 -> ip = get_prefix(ip, cur_node -> prefix + 1);
            next1 -> port = port;
            next1 -> prefix = cur_node -> prefix + 2;
            next1 -> has = 1;
            next1 -> children[0] = next1 -> children[1] = NULL;
            next1 -> children[2] = next1 -> children[3] = NULL;
            next1 -> is_odd = 1;
            next1 -> compress = 4;
            cur_node -> children[cur_bit1 << 1] = next1;
            cur_node -> compress = cur_node -> compress -1;
        }

        next2 = cur_node -> children[(cur_bit1 << 1) | 0x1];
        if (next2 == NULL) {
            next2 = (TrieNodeadv*)malloc(sizeof(TrieNodeadv));
            next2 -> ip = get_prefix(ip, cur_node -> prefix + 1);
            next2 -> port = port;
            next2 -> prefix = cur_node -> prefix + 2;
            next2 -> has = 1;
            next2 -> children[0] = next2 -> children[1] = NULL;
            next2 -> children[2] = next2 -> children[3] = NULL;
            next2 -> is_odd = 1;
            next2 -> compress = 4;
            cur_node -> children[cur_bit1 << 1 | 0x1] = next2;
            cur_node -> compress = cur_node -> compress -1;
        }
        cur_node = NULL;
    }
    

    if (cur_node != NULL) {
        cur_node -> port = port;
        cur_node -> has = 1;
    }
    root -> prefix = ori_prefix;
}


static inline uint32_t advanced_find_ip(TrieNodeadv *root, uint32_t ip) {
    //printf("3");
    TrieNodeadv *match = NULL;
    TrieNodeadv *cur = root;
    if(cur == NULL){
        return -1;
    }
    int cur_bit;
    char cip[30] = "74.182.10.124";
    int uip = convert_ip_to_uint(cip);
    if(ip==uip)
        printf("%d ip %u prefix %u\n",i,cur->ip, cur->prefix);

    if (cur -> prefix < PREFIX_LEN) {
        if (cur -> has && cur -> ip == get_prefix(ip, cur -> prefix - cur -> is_odd)) {
            match = cur;
        }
        if(ip==uip)
                printf("%d ip %u prefix %u\n",i,cur->ip, cur->prefix);
    }

    while(cur) {
        int prefix = 0;
        int j=-1;
        for(int i=0;i<4;i++){
            if(cur->children[i]== NULL){
                continue;
                printf("null %d",i);
            }
            if(ip==uip)
                printf("%d ip %u prefix %u\n",i,cur->children[i]->ip, cur->children[i]->prefix);
            if (cur -> children[i]->has && cur -> children[i]->ip == get_prefix(ip, cur -> children[i]->prefix - cur -> children[i]->is_odd)) {
                match = cur-> children[i];
                if(ip==uip)
                    printf("match");
                j=i;
                break;
            }
            
        }
        
        cur = j<0 ? NULL : cur -> children[j];
        if(ip==uip){
            printf("ip %u prefix len %u, port%d\n",match->ip,match->prefix,match->port);
            if(cur==NULL)
                printf("null,j%d\n",j);
        }
    }

    return match? match -> port : -1;

}


// Constructing an advanced trie-tree to lookup according to `forwardingtable_filename`
void create_tree_advance(const char* forward_file) {
   FILE *fp = fopen(forward_file, "r");
    if (fp == NULL) {
        perror("Open source file fails");
        exit(1);
    }

    // trieadv = trieadv_init();
    superTrie = superTrie_init();
    char sip[30];
    int prefix, port_num;

    int cnt = 0;
    while (!feof(fp)) {
        fscanf(fp, "%s %d %d", sip, &prefix, &port_num);
        uint32_t uip = convert_ip_to_uint(sip);
        if (prefix >= PREFIX_LEN) {
            TrieNodeadv *root = superTrie -> children[(unsigned int)(0xffff0000 & uip) >> PREFIX_LEN];
            branch_tree(root, uip, port_num, prefix);
        } else {
            uint32_t start = (get_prefix(uip, prefix)) >> PREFIX_LEN;
            uint32_t end = start + (1 << (PREFIX_LEN - prefix));
            for (int i = start; i < end; i++) {
                if (!superTrie -> children[i] -> has || !(superTrie -> children[i] -> prefix > prefix)) {
                    superTrie -> children[i] -> ip = get_prefix(uip, prefix);
                    superTrie -> children[i] -> prefix = prefix;
                    superTrie -> children[i] -> has = 1;
                    superTrie -> children[i] -> port = port_num;
                    superTrie -> children[i] -> is_odd = 0;
                }
            }
        }
        cnt++;
    }
    //fprintf("step into compress");

    //compress_tree(superTrie);


}

// Look up the ports of ip in file `lookup_file` using the advanced tree
uint32_t *lookup_tree_advance(uint32_t* ip_vec) {
    //printf("1");
    uint32_t *res = (uint32_t*)malloc((TEST_SIZE+1)*sizeof(uint32_t));
    for (int i = 0; i < TEST_SIZE; i++) {
        uint32_t ip = ip_vec[i];
        //printf("2");
        TrieNodeadv *find_root = superTrie -> children[(unsigned int)(0xffff0000 & ip) >> PREFIX_LEN];
        res[i] = advanced_find_ip(find_root, ip);
    }
    return res;
}

void compress_tree(SuperTrieNode *superTrie) {
    for (int i = 0; i < BRANCH; i++) {
        TrieNodeadv *cur_node = superTrie->children[i];
        if (cur_node->compress == 3 && cur_node->has == 0) {
            // Combine children using bitwise OR
            superTrie->children[i] = superTrie->children[i]->children[0] ?  superTrie->children[i]->children[0] :
                                    (superTrie->children[i]->children[1] ? superTrie->children[i]->children[1] :
                                    (superTrie->children[i]->children[2] ? superTrie->children[i]->children[2] : superTrie->children[i]->children[3]));
            
            free(cur_node);
        }
        search(superTrie->children[i]);

        // Free the individual children
        

        // Optionally, free superTrie->children[i] if needed
        // free(superTrie->children[i]);
    }
}

void search(TrieNodeadv *root){
    if(root == NULL){
        return;
    }
    for(int i=0;i<4;i++){
        if(root->children[i] == NULL){
            continue;
        }
        if (root->children[i]->compress == 3 && root->children[i]->has == 0) {
            // Combine children using bitwise OR
            TrieNodeadv *cur_node = root->children[i];
            root ->children[i]= root->children[i]->children[0] ?  root->children[i]->children[0] :
                                    (root->children[i]->children[1] ? root->children[i]->children[1] :
                                    (root->children[i]->children[2] ? root->children[i]->children[2] : root->children[i]->children[3]));
            
            /*if(cur_node->prefix != root->children[i]->prefix){
                printf("prefix problem");
            }*/
            free(cur_node);
        }
        search(root->children[i]);
    }
    
}