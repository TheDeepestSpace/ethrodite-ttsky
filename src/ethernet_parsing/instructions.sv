// ============================================================================
// TCP PROCESS PROCEDURE – HIGH-LEVEL STEPS & STATE MACHINE
// ----------------------------------------------------------------------------
// This comment describes the sequence of actions and internal bookkeeping 
// required for a TCP-style reliable, ordered, acknowledged stream protocol.
// It assumes you have primitives to send and receive “packets” (segments) 
// with headers (seq, ack, flags, window, etc) and data payloads.
// ----------------------------------------------------------------------------
//
// 1) Initialization / setup  
//    - initialize local variables/state:  
//        • local sequence number (our_seq) ← random (or defined) initial value  
//        • remote sequence number (their_seq) ← undefined / zero until handshake  
//        • send window size, receive window size ← configured defaults  
//        • congestion control variables (if used): cwnd, ssthresh, etc  
//        • retransmission timer(s), timeout values, outstanding segments buffer  
//        • flags/booleans: connection_active, fin_sent, fin_received, etc  
//    - bind to or open “socket” (if applicable) – define local port, remote IP/port  
//    - prepare to accept or initiate connection (passive vs active)  
//
// 2) Connection establishment (three-way handshake)  
//    If acting as client (active open):  
//      a) Send SYN segment:  
//         • flags.SYN = 1, flags.ACK = 0, flags.FIN = 0  
//         • our_seq = initial_seq  
//         • send segment with seq = our_seq, no data, window = recv_window  
//      b) Start timer for SYN (in case no reply)  
//      c) Wait for incoming segment from remote with flags.SYN+ACK:  
//         • check remote flags.SYN==1 && flags.ACK==1  
//         • remote their_seq = received.seq  
//         • ensure ack number = our_seq+1  
//      d) Send ACK segment back:  
//         • flags.ACK=1 (and possibly flags.SYN=0)  
//         • seq = our_seq+1 (or our_seq if no data)  
//         • ack = their_seq+1  
//         • window = recv_window  
//      e) Mark connection_active = true  
//
//    If acting as server (passive open):  
//      a) Wait for SYN from client  
//      b) On receiving SYN: their_seq = received.seq ; send SYN+ACK back:  
//         • flags.SYN=1, flags.ACK=1  
//         • seq = our_seq (initial)  
//         • ack = their_seq+1  
//         • window = recv_window  
//         • start timer for this half-handshake if applicable  
//      c) Wait for ACK from client: flags.ACK=1, ack = our_seq+1  
//      d) Mark connection_active = true  
//
// 3) Data transfer  
//    While connection_active && (not closing):  
//      a) **Sending data**:  
//         • If upper-layer/application gives data to send: fragment or chunk into payloads  
//         • For each chunk: set seq = next_unsent_seq ; ack = latest_received_seq+1 ; flags.ACK=1 ; window = recv_window  
//         • Place in “outstanding segments buffer” (for possible retransmit)  
//         • Transmit the segment via send_primitive  
//         • Start/refresh retransmission timer for that segment  
//         • Update next_unsent_seq += payload_length  
//      b) **Receiving data**:  
//         • On receiving an incoming segment with flags.ACK= maybe or data:  
//             – If data payload present: check seq == expected_recv_seq (or > expected => out-of-order)  
//             – If in-order: deliver data to upper layer; expected_recv_seq += payload_length  
//             – Send back ACK: seq = our_current_seq ; ack = expected_recv_seq ; flags.ACK=1 ; window = recv_window  
//         • If duplicate or out-of-order: buffer or discard as per policy, send duplicate ack if desired  
//      c) **Processing ACKs**:  
//         • On receiving a segment with flags.ACK=1 and ack number > last_ack_received:  
//             – Remove from outstanding buffer all segments with seq+length < ack  
//             – Stop their retransmit timers  
//             – Possibly slide send window, increase cwnd (if congestion control)  
//             – Update last_ack_received = ack-1  
//         • If ack number <= last_ack_received: duplicate ack => may trigger fast-retransmit if policy  
//      d) **Flow control / window management**:  
//         • Keep track of remote advertised window (from remote’s “window” field)  
//         • Ensure you don’t send more data than allowed: (next_unsent_seq – unacked_seq) < remote_window  
//      e) **Retransmissions / timeout**:  
//         • If retransmission timer fires for a segment:  
//             – Retransmit segment  
//             – Possibly reduce cwnd, adjust ssthresh (if congestion control)  
//             – Restart timer  
//      f) **Congestion control (optional)**:  
//         • On new ACKs: increase cwnd (slow start / congestion avoidance)  
//         • On loss (timeout / fast-retransmit): set ssthresh = cwnd/2 ; cwnd = initial or 1 MSS ; etc  
//
// 4) Connection termination (four-way handshake)  
//    When either side/application wishes to close (gracefully):  
//      a) Send FIN segment: flags.FIN=1, flags.ACK=1 ; seq = next_unsent_seq ; ack = latest_received_seq+1 ; window = recv_window  
//         • Mark fin_sent = true  
//      b) Wait for ACK of our FIN: on receiving flags.ACK=1 and ack = our_seq_at_fin+1  
//      c) Wait (or send) remote’s FIN when remote has no more data: on receiving FIN: flags.FIN=1 ; ack = their_seq+1 ; deliver ack back with flags.ACK=1  
//      d) After our ACK of their FIN – both sides done sending – enter TIME_WAIT (optional) or directly close depending on implementation  
//      e) On timeout of TIME_WAIT (or immediately): cleanup connection state: connection_active = false ; free buffers ; reset variables  
//
// 5) Error / reset handling  
//    - If receive a segment with flags.RST=1: immediate abort of connection; free buffers; notify upper layer  
//    - If invalid segment (bad checksum if you detect, or unknown seq/ack): ignore or send RST per policy  
//    - If window advertisement is zero: implement persist timer so that you eventually send a “window probe” when remote window opens  
//
// 6) State cleanup and reuse  
//    - After connection closure or abort: ensure all timers canceled, outstanding buffers cleared, state variables reset to “closed” or “idle”  
//    - Optionally: enter “time_wait” state for boundary condition handling (if implementing full TCP semantics)  
//    - Prepare to either listen / accept another connection (server) or to initiate new connection (client)  
//
// ----------------------------------------------------------------------------
// Notes / implementation hints:  
//  • Use sequence-numbers on a per-byte basis (not per-segment) to allow ordering and retransmission. :contentReference[oaicite:0]{index=0}  
//  • Maintain sliding window for flow control: sender may send up to remote_window bytes un-ACKed. :contentReference[oaicite:1]{index=1}  
//  • Implement timers per sent segment (or group) to detect loss and trigger retransmit.  
//  • Keep a buffer of un-ACKed segments so you can retransmit them.  
//  • For simplicity you may skip full congestion control (cwnd, ssthresh) initially; but you must still handle window and retransmit.  
//  • Use flags (SYN, ACK, FIN, RST) properly in the header. :contentReference[oaicite:2]{index=2}  
//  • For data reception: ensure correct in-order delivery to upper layer; handle duplicates/out‐of-order as needed.  
//  • On connection close: both sides must send FIN and wait for ACK. Four steps. :contentReference[oaicite:3]{index=3}  
//
// ============================================================================
// End of procedure comment block.
// ============================================================================
