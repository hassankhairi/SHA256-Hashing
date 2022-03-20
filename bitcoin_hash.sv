module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;
parameter NUM_OF_WORDS=20;

//list of states
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, MORE_COMPUTE,WRITE} state;

//array to hold the input output values and w values for calculation
logic [31:0] hout[num_nonces];
logic [31:0] message[19];
logic [31:0] wxx[16];
logic [31:0] w[num_nonces][num_nonces];

//h0-h7 values and a-h values for word expension and sha operation
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] a, b, c, d, e, f, g, h;

//mainly will be used as counters and indicators
logic [ 7:0] i, j;

//to work with address and indicating 
logic [15:0] offset; // in word address
logic cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;

//start_mod and done_mod will be used when inistantiate the SHA-256 modules
logic done_mod[16];
logic start_mod;

logic [ 7:0] num_blocks;

/*
  combination logic connecting the memory ports with local variables
*/
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;



parameter int k[64] = '{
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

/*
  determine_num_blocks determines the number of 512 bits blocks it need to make based on the input. 
  Since input is given as words(32 bits), each block will contain 16 words(16*32=512 bits)
*/
function logic [15:0] determine_num_blocks(input logic [31:0] size);
  size=size+1;
  determine_num_blocks=(size>>4)+32'd1;
endfunction

/*
  sha256_op does the main SHA operations based on the input parameters
*/
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, ww,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1  = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch  = (e & f) ^ ((~e) & g);
    t1  = h + S1 + ch + k[t] + ww;
    S0  = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2  = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction


function logic [31:0] rightrotate(input logic [31:0] x,input logic [ 7:0] r);
   rightrotate= (x >> r) | (x << (32-r));
endfunction

/*
  word expansion function for SHA operation optimized version
*/
function logic [31:0] wtnew; // function with no inputs
  logic [31:0] s0, s1;
  s0 = rightrotate(wxx[1],7)^rightrotate(wxx[1],18)^(wxx[1]>>3);
  s1 = rightrotate(wxx[14],17)^rightrotate(wxx[14],19)^(wxx[14]>>10);
  wtnew = wxx[0] + s0 + wxx[9] + s1;
endfunction


/*
    In this main design, we will first calculate the hash based on the first 16 words of the input message. 
    While at the same time, with the left over 3 words,  we will also prepare 16 more w arrays with difference 
    nonce values. Our goal is to utilize parallel computer with modules which will take care of phase 2 and 3 
    calculation. 
*/
always_ff @(posedge clk, negedge reset_n) 
begin 
    if (!reset_n) begin
        start_mod<=0;
        cur_we <= 1'b0;
        state <= IDLE;
    end else case (state) 
        IDLE: begin
            if(start)begin
                h0 <= 32'h6a09e667;
                h1 <= 32'hbb67ae85;
                h2 <= 32'h3c6ef372;
                h3 <= 32'ha54ff53a;
                h4 <= 32'h510e527f;
                h5 <= 32'h9b05688c;
                h6 <= 32'h1f83d9ab;
                h7 <= 32'h5be0cd19; 
                a <= 32'h6a09e667;
                b <= 32'hbb67ae85;
                c <= 32'h3c6ef372;
                d <= 32'ha54ff53a;
                e <= 32'h510e527f;
                f <= 32'h9b05688c;
                g <= 32'h1f83d9ab;
                h <= 32'h5be0cd19; 
//start_mod will be controlling when the sha modules for phase 2 and 3 will begin calculating
                start_mod<=0;
                i<=0;
                j<=0;
                cur_addr<=message_addr;
                offset<=0;
                state<=BLOCK;
            end else begin
                state<=IDLE;
            end 
        end
/*
READ state will read in the the input and store in message
The first 16 words will also be store in w array to reduce cycles 
*/
        READ: begin
            message[offset]<=mem_read_data;
            wxx[offset]<=mem_read_data;
            state<=BLOCK;
            if(offset==NUM_OF_WORDS-2) begin
                j<=1;
                offset<=0;
            end else begin
                offset<=offset+1;
            end
        end

/*
BLOCK state we will be preparing 16 more w array with difference nonce values 
for phase 2 and 3 calculations
*/
        BLOCK: begin
            //allowing for reading 
            if(j==0) begin 
                state<=READ;
            end else begin
                //construction of arrays for phase 2 
                for(int y=0; y<3; y++) begin
                    for(int z=0; z<num_nonces; z++ )begin
                        w[z][y]<=message[16+y];
                    end
                end

                w[0][3]<=32'd0;
                w[1][3]<=32'd1;
                w[2][3]<=32'd2;
                w[3][3]<=32'd3;
                w[4][3]<=32'd4;
                w[5][3]<=32'd5;
                w[6][3]<=32'd6;
                w[7][3]<=32'd7;
                w[8][3]<=32'd8;
                w[9][3]<=32'd9;
                w[10][3]<=32'd10;
                w[11][3]<=32'd11;
                w[12][3]<=32'd12;
                w[13][3]<=32'd13;
                w[14][3]<=32'd14;
                w[15][3]<=32'd15;

                for(int y=0; y<num_nonces; y++)begin
                    w[y][4]<=32'h80000000;
                end

                for(int y=0; y<num_nonces; y++)begin
                    for(int z=5; z<num_nonces-1; z++)begin
                        w[y][z]<=32'h00000000;
                    end
                end 
                for(int y=0; y<num_nonces; y++)begin
                    w[y][15]<=32'd640;
                end
                offset<=0;
                state<=COMPUTE;
            end
        end

/*
COMPUTE state does SHA related operations for first block and the result will be part of parameter 
for modules which will process phase 2 and 3
*/
        COMPUTE: begin
            if (i < 64) 
            begin
              for (int n = 0; n < 15; n++) begin
                wxx[n] <= wxx[n+1]; 
                wxx[15] <= wtnew();
              end
              {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, wxx[0], i);
              i<=i+1;
              state<=COMPUTE;
            end else 
            begin
              h0 <= h0 + a;
              h1 <= h1 + b;
              h2 <= h2 + c;
              h3 <= h3 + d;
              h4 <= h4 + e;
              h5 <= h5 + f;
              h6 <= h6 + g;
              h7 <= h7 + h; 
              state<=MORE_COMPUTE;  
            end 
        end
/*
MORE_COMPUTE state, here we will start processing the modules and wait for the calculations to be finish
and when it is finished, then we start preparing for writing and memory addresses
*/
        MORE_COMPUTE: begin
            start_mod<=1; 
            if(done_mod[0]!==1)begin 
                state<=MORE_COMPUTE;
            end else begin
                cur_we<=1;
                cur_addr<=output_addr;
                cur_write_data<=hout[0];
                state<=WRITE;    
            end

        end

/*
WRITE state iterated through the 16 values h0[0] to h0[15] and write to the memory
*/
        WRITE: begin
            if(offset<15)begin
                cur_write_data<=hout[offset+1];
                offset<=offset+1;
                state<=WRITE;
            end else begin
                state<=IDLE;
            end
        end

    endcase
    end

/*
Here we use generate and genvar to process the 16 arrays and the module itself will process
the rest of phase 3 and phase 3. And after inistantiation, our job is simply to obtain the necessary outputs
*/
genvar m;
generate
    for(m=0; m<num_nonces; m=m+1) begin: sha_loop
        sha256_unit sha_inst(
            .clk(clk),
            .start(start_mod),                
            .done(done_mod[m]),              
            .input_message(w[m]),
				.k(k),
            .reset_n(reset_n),
            .input_hash0(h0),
            .input_hash1(h1),
            .input_hash2(h2),
            .input_hash3(h3),
            .input_hash4(h4),
            .input_hash5(h5),
            .input_hash6(h6),
            .input_hash7(h7),
            .output_mod(hout[m]));
    end: sha_loop
endgenerate

assign done= (state==IDLE);
endmodule