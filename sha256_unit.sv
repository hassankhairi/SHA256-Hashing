module sha256_unit(
	input logic  clk, start, reset_n,
	input int k[0:63], 
	input logic [31:0] input_message[16],
	input logic [31:0] input_hash0, input_hash1, input_hash2, input_hash3, input_hash4, input_hash5, input_hash6, input_hash7,
	output logic done,
	output logic [31:0] output_mod
);

enum logic[1:0]{IDLE, BLOCK, COMPUTE, WRITE} state;

logic [31:0] a, b, c, d, e, f, g, h;
logic [31:0] w[16];
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [ 7:0] i, j;

function logic [31:0] rightrotate(input logic [31:0] x,input logic [ 7:0] r);
   rightrotate= (x >> r) | (x << (32-r));
endfunction

function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
	begin
		logic [31:0] S1, S0, ch, maj, t1, t2;
		S1  = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		ch  = (e & f) ^ ((~e) & g);
		t1  = h + S1 + ch + k[t] + w;
		S0  = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		maj = (a & b) ^ (a & c) ^ (b & c);
		t2  = S0 + maj;
		sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	end
endfunction

//assign done=done_s;

function logic [31:0] wtnew;
	logic [31:0] s0, s1;
	s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3);
	s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10);
	wtnew = w[0] + s0 + w[9] + s1;
endfunction



always_ff @(posedge clk, negedge reset_n)
begin
	if (!reset_n) begin
		state <= IDLE;
	end 
	else case (state)
		IDLE: begin 
			if(start)begin
				w <= input_message;
				
				h0 <= 32'h6a09e667;
            h1 <= 32'hbb67ae85;
            h2 <= 32'h3c6ef372;
            h3 <= 32'ha54ff53a;
            h4 <= 32'h510e527f;
            h5 <= 32'h9b05688c;
            h6 <= 32'h1f83d9ab;
            h7 <= 32'h5be0cd19; 
				
            a <= input_hash0;
            b <= input_hash1;
            c <= input_hash2;
            d <= input_hash3;
            e <= input_hash4;
            f <= input_hash5;
            g <= input_hash6;
            h <= input_hash7;
   
            i <= 0;
            j <= 0;
				
            state <= COMPUTE;
			end
      end
    COMPUTE: begin
      if (i < 64) 
			begin
				for (int n = 0; n < 15; n++) begin
					w[n] <= w[n+1]; 
					w[15] <= wtnew();
				end
         {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[0], i);
         i <= i + 1;
         state <= COMPUTE;
		end else begin
         if(j == 1) begin
				state <= WRITE;
         end else 
            begin
					w[0] <= input_hash0 + a;
					w[1] <= input_hash1 + b;
					w[2] <= input_hash2 + c;
					w[3] <= input_hash3 + d;
					w[4] <= input_hash4 + e;
					w[5] <= input_hash5 + f;
					w[6] <= input_hash6 + g;
					w[7] <= input_hash7 + h;
					w[8] <= 32'h80000000;
					w[9] <= 32'h00000000;
					w[10] <= 32'h00000000;
					w[11] <= 32'h00000000;
					w[12] <= 32'h00000000;
					w[13] <= 32'h00000000;
					w[14] <= 32'h00000000;
					w[15] <= 32'd256;
					
					a <= h0;
					b <= h1;
					c <= h2;
					d <= h3;
					e <= h4;
					f <= h5;
					g <= h6;
					h <= h7;
					
					i <= 0;
					j <= j + 1;
					
					state <= COMPUTE;
            end
          end 
      end 
		WRITE: begin
			output_mod <= a + h0;
			done <= 1;
			state <= IDLE;
		end
	endcase
end
endmodule
