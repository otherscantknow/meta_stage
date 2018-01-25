#ifndef META_H
#define META_H

#include "cache.h"

#include<set>
#include<iterator>

// L2 VLDP
// #define L2_PF_DEBUG_PRINT
#ifdef L2_PF_DEBUG_PRINT
#define L2_PF_DEBUG(x) x
#else
#define L2_PF_DEBUG(x)
#endif

#define X 0.5
#define RR_INDEX 8
#define NUM_RR_ENTRIES (1 << RR_INDEX)
#define NUM_PREFETCHERS 7
#define CHECK_SCORE 2048

/*
Order:
next_line - 0
ip_stride - 1
sandbox - 2
BO - 3
VLDP - 4
SPP - 5
stream - 6
*/
//ip_stride
#define IP_TRACKER_COUNT 1024
#define IP_PREFETCH_DEGREE 3

class IP_TRACKER {
  public:
    // the IP we're tracking
    uint64_t ip;

    // the last address accessed by this IP
    uint64_t last_cl_addr;

    // the stride between the last two addresses accessed by this IP
    int64_t last_stride;

    // use LRU to evict old IP trackers
    uint32_t lru;

    IP_TRACKER () {
        ip = 0;
        last_cl_addr = 0;
        last_stride = 0;
        lru = 0;
    };
};

extern IP_TRACKER trackers[IP_TRACKER_COUNT];
IP_TRACKER trackers[IP_TRACKER_COUNT];

// void ip_stride_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, uint8_t type);

//next_line
// void next_line_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, uint8_t type);

//sandbox
#define SB_NOFFSETS 32
#define MAX_L2_ACCESSES 256
#define PF1_ACCURACY 256
#define PF2_ACCURACY 512
#define PF3_ACCURACY 768
#define MAX_PREFETCHES 8

/* ------------------------------------------------------------------- */

struct MinCompare
{
    bool operator()(pair<int,int> p1, pair<int,int> p2)
    {
        return p1.second < p2.second;
    }

};

set< pair<int , int>, MinCompare > offset_scores;		// stores the offset and score for each round
set<pair<int,int>> candidate_prefetchers;					// prefetchers whose score is higher than threshold and used for actual memory access
int l2_access_counter = 0;				// maintains the number of L2 cache accesses for each evaluation period
int current_evaluation_offset = -8;	// offset being evaluated in the present evaluation period
int current_offset_score = 0;			// score of offset being presently evaluated
set<uint64_t> sandbox;					// sandbox
int last_max_offset = 8;				// maintains the maximum value of offset for the current round
set<int> discarded_offsets;			// offsets discarded due to lower score than threshold
set<int> evaluate_offsets;				// offsets to be evaluated in current round


void evaluate_prefetchers_initialize();
void offset_scores_initialize();
void offset_scores_reset();
bool sandbox_exists(uint64_t line_addr);
void sandbox_clear();
void select_candidate_prefetchers(int offset, int score);
void offset_scores_clear();
void evaluate_offsets_add_new();
void candidate_evaluation(uint64_t line_addr);
// void sandbox_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, uint8_t type);


//BO_pref
#define DEFAULT_OFFSET 1
#define BO_NOFFSETS 46
#define RRINDEX 8
#define RRTAG 12
#define SCOREMAX 31
#define ROUNDMAX 100
#define BADSCORE 1
#define DELAYQSIZE 15

/* ------------------------------------------------------------------- */

#define TRUNCATE(x,nbits) (((x) & ((1<<(nbits))-1)))

#define SAMEPAGE(lineaddr1,lineaddr2) ((((lineaddr1) ^ (lineaddr2)) >> LOG2_BLOCK_SIZE) == 0)

#define INCREMENT(x,n) {x++; if (x==(n)) x=0;}

int OFFSET[BO_NOFFSETS] = {1,-1,2,-2,3,-3,4,-4,5,-5,6,-6,7,-7,8,-8,9,-9,10,-10,11,-11,12,-12,13,-13,14,-14,15,-15,16,-16,18,-18,20,-20,24,-24,30,-30,32,-32,36,-36,40,-40};
int recent_request[1<<RRINDEX]; 
int prefetch_offset=1;

struct offsets_scores {
  int score[BO_NOFFSETS];		// maintains scores of each offset being considered		    
  int max_score;          	// maintains maximum score for a particular learning phase
  int best_offset;        	// best offset for a particular learning phase
  int round;              	// latest round number 
  int last;                   	// index of next offset to be considered in the learning phase
} offset_score;                     


struct delay_queue {
  int lineaddr[DELAYQSIZE];	// array for implementation of the queue of addresses  
  int valid[DELAYQSIZE];    	// for checking if slot at some index of key is available or not
  int tail;                 	
  int head;                 
} delay_q;   

void rr_initialize();
void rr_insert(uint64_t addr);
int rr_hit(uint64_t addr);
void offset_reset();
void dq_initialize();
void dq_push(uint64_t addr);
int dq_ready();
void dq_pop();
void learning_phase(uint64_t addr);
uint64_t issue_prefetch(uint64_t addr);
// void BO_operate(uint64_t addr, uint64_t ip, uint8_t cache_hit, uint8_t type);


//vldp
int L2_DHB_update(uint32_t cpu,uint64_t addr);
void L2_OPT_update(uint32_t cpu, uint64_t addr, int last_block);
void L2_DPT_update(uint32_t cpu,uint64_t addr, int entry);
int L2_DPT_check(uint32_t cpu, int *delta, int entry);
uint64_t L2_OPT_check(uint32_t cpu, uint64_t addr);
int L2_DPT_check(uint32_t cpu, int *delta, uint64_t curr_block);
void L2_promote(uint32_t cpu, int entry, int table_num);


//kpcp/SPP
#define PF_THRESHOLD 25
#define FILL_THRESHOLD 75
#define LOOKAHEAD_ON
#define GC_WIDTH 10
#define GC_MAX ((1<<GC_WIDTH)-1)

int num_pf[NUM_CPUS], curr_conf[NUM_CPUS], curr_delta[NUM_CPUS], MAX_CONF[NUM_CPUS];
int out_of_page[NUM_CPUS], not_enough_conf[NUM_CPUS];
int pf_delta[NUM_CPUS][L2C_MSHR_SIZE], PF_inflight[NUM_CPUS];
int spp_pf_issued[NUM_CPUS], spp_pf_useful[NUM_CPUS], spp_pf_useless[NUM_CPUS];
int useful_depth[NUM_CPUS][L2C_MSHR_SIZE], useless_depth[NUM_CPUS][L2C_MSHR_SIZE];
int conf_counter[NUM_CPUS];

int PF_check(uint32_t cpu, int signature, int curr_block);
int st_prime = L2_ST_PRIME, pt_prime = L2_PT_PRIME;

class PF_buffer {
  public:
    int delta,
        signature,
        conf,
        depth;

    PF_buffer() {
        delta = 0;
        signature = 0;
        conf = 0;
        depth = 0;
    };
};
PF_buffer pf_buffer[NUM_CPUS][L2C_MSHR_SIZE];

void GHR_update(uint32_t cpu, int signature, int path_conf, int last_block, int oop_delta);
int check_same_page(int curr_block, int delta);
int PF_check(uint32_t cpu, int signature, int curr_block);


//meta_pref
class RECENT_REQUEST_TABLE {
	public:
		uint64_t tag[NUM_RR_ENTRIES],
				 pref_req[NUM_RR_ENTRIES],
				 pref_useful[NUM_RR_ENTRIES];

	RECENT_REQUEST_TABLE() {
		for (int i=0; i<NUM_RR_ENTRIES; i++){
			tag[i] = 0;
			pref_req[i] = 0;
			pref_useful[i] = 0;}
	};
};

extern RECENT_REQUEST_TABLE L2_RR[NUM_CPUS][NUM_PREFETCHERS];
RECENT_REQUEST_TABLE L2_RR[NUM_CPUS][NUM_PREFETCHERS];


#endif




