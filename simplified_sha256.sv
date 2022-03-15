module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);

// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, WRITE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [31:0] w[64];
logic [31:0] message[20];
logic [31:0] wt;
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a, b, c, d, e, f, g, h;
logic [ 7:0] i, j;
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [512:0] memory_block;
logic [ 7:0] tstep;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
assign tstep = (i - 1);

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);

  // Student to add function implementation

endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    // Student to add remaning code below
    // Refer to SHA256 discussion slides to get logic for this function
    ch = 
    t1 = 
    S0 = 
    maj = 
    t2 = 
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction


// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
       if(start) begin
       // Student to add rest of the code  




       end
    end

    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory
    BLOCK: begin
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation
       



   




    

    end

    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
    COMPUTE: begin
	// 64 processing rounds steps for 512-bit block 
        if (i <= 64) begin














        end
    end

    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
    WRITE: begin
   


    end
   endcase
  end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule
