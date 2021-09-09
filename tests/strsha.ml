open Merkle
(*

strcha.ml is a test file that instantiates a context for a merkle tree composed 
of the string type to represent the data contained in the nodes of the tree, 
and the "sha" library <https://github.com/djs55/ocaml-sha> to manage the cryptographic part.

*)

module StrShaCtx = struct
  type data = string
  type digest = Sha256.t
  let hash el = el |> Sha256.string
  let string_hex_of_hash el = Sha256.to_hex el
  let to_string = string_hex_of_hash
  let concat_hashes h1 h2 = hash (String.concat "" [to_string h1; to_string h2])
  
  (** sha doesn't have equal function, 
      contrary to what is written in the mli of the library *)
  let equal h1 h2 = (to_string h1) = (to_string h2)
  
end

module MtreeStrSha = MerkleTree(StrShaCtx)

module To_test = struct
  let of_txs = MtreeStrSha.mtree_of_txs
  let witness = MtreeStrSha.witness
  let proof = MtreeStrSha.proof
end

(** utils functions for alcotest *)
let print_mtree ppf mtree = Fmt.pf ppf "Merkle tree : %s" (MtreeStrSha.to_string mtree)
let mtree_eq m m' = MtreeStrSha.equal m m'
let mtree_testable = Alcotest.testable print_mtree mtree_eq

let direction_to_string dir = match dir with | MtreeStrSha.L -> "left" | MtreeStrSha.R -> "right"
let print_proof ppf proof = Fmt.pf ppf "Proof : %s" 
  (String.concat "\n" (List.map (fun (x,y) -> String.concat "" ["(";StrShaCtx.to_string x;",";direction_to_string y;")"]) proof))
let proof_eq p p' = let mapstr = List.map (fun (x,y) -> (StrShaCtx.to_string x,y)) in (mapstr p) = (mapstr p')

let proof_testable = Alcotest.testable print_proof proof_eq

(** ecrire un module de test parametre *)

(** utils data for testing functions *)

let mtree4 =
  "50a504831bd50fee3581d287168a85a8dcdd6aa777ffd0fe35e37290268a0153
  b30ab174f7459cdd40a3acdf15d0c9444fec2adcfb9d579aa154c084885edd0a
    559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd
    df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c
  26b5aabe804fe5d533c663dea833e8078188376ce5ca2b5c3371d09ef6b0657b
    6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d
    3f39d5c348e5b79d06e842c114e6cc571583bbf44e4b0ebfda1a01ec05745d43
"

let mtree5 =
  "9297867c9b3c40ef840433442aabca36dde10c095911944a6705e8905622735a
  50a504831bd50fee3581d287168a85a8dcdd6aa777ffd0fe35e37290268a0153
    b30ab174f7459cdd40a3acdf15d0c9444fec2adcfb9d579aa154c084885edd0a
      559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd
      df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c
    26b5aabe804fe5d533c663dea833e8078188376ce5ca2b5c3371d09ef6b0657b
      6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d
      3f39d5c348e5b79d06e842c114e6cc571583bbf44e4b0ebfda1a01ec05745d43
  4441435e9da65331ce2eccf7aca694c30acbb8289111964f9948db710915d819
    a9f51566bd6705f7ea6ad54bb9deb449f795582d6529a0e22207b8981233ec58
    a9f51566bd6705f7ea6ad54bb9deb449f795582d6529a0e22207b8981233ec58
"

let mtree9 = 
  "79d9abdd3a107def31e5fa01b97d4e12c96d5caf3206bc10ab095dd30ac1fbf6
  e3caa45a951457b84493e3adec8265f99311c3b1b4f28befbb067a1912efab9e
    50a504831bd50fee3581d287168a85a8dcdd6aa777ffd0fe35e37290268a0153
      b30ab174f7459cdd40a3acdf15d0c9444fec2adcfb9d579aa154c084885edd0a
        559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd
        df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c
      26b5aabe804fe5d533c663dea833e8078188376ce5ca2b5c3371d09ef6b0657b
        6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d
        3f39d5c348e5b79d06e842c114e6cc571583bbf44e4b0ebfda1a01ec05745d43
    f77f77255d1a716691a8454dfe6521fa29d3bb6d198960beaf252a8fc3d36ee1
      3839c2a21cb4b6133276b6d7fb557aa92acdf32a54553f5ecd32501b61ab9fac
        a9f51566bd6705f7ea6ad54bb9deb449f795582d6529a0e22207b8981233ec58
        f67ab10ad4e4c53121b6a5fe4da9c10ddee905b978d3788d2723d7bfacbe28a9
      cd56020b9a99b481039af6d59664b1e7095a3d6b5af26b24b14bacbe9a8bac72
        333e0a1e27815d0ceee55c473fe3dc93d56c63e3bee2b3b4aee8eed6d70191a3
        44bd7ae60f478fae1061e11a7739f4b94d1daf917982d33b6fc8a01a63f89c21
  22a16ec5826bea3a87ab680b89ac7c52df96e467cb49b42f435fae69176e28bb
    a83dd0ccbffe39d071cc317ddf6e97f5c6b1c87af91919271f9fa140b0508c6c
    a83dd0ccbffe39d071cc317ddf6e97f5c6b1c87af91919271f9fa140b0508c6c
"


let proof_included = let hash_e = StrShaCtx.hash "E" in
  let hash_cd = StrShaCtx.concat_hashes (StrShaCtx.hash "C") (StrShaCtx.hash "D") in 
  let hash_ee = StrShaCtx.concat_hashes hash_e hash_e in
  [(StrShaCtx.hash "B",MtreeStrSha.L); (hash_cd,L); (hash_ee,L)]

let mtreeEx = To_test.of_txs ["A";"B";"C";"D";"E"]
let wtnEx = To_test.witness "A" mtreeEx
let badWtnEx = To_test.witness "E" mtreeEx

(*TEST FUNCTIONS*)

let test_of_txs_empty () = 
  Alcotest.(check mtree_testable) "same merkle tree" Empty (To_test.of_txs [])

let test_of_txs_even () = 
  Alcotest.(check string) "same merkle tree" mtree4 (MtreeStrSha.to_string(To_test.of_txs ["A";"B";"C";"D"]))

let test_of_txs_odd5 () = 
  Alcotest.(check string) "same merkle tree" mtree5 (MtreeStrSha.to_string(mtreeEx))

let test_of_txs_odd9 () = 
  Alcotest.(check string) "same merkle tree"  mtree9 (MtreeStrSha.to_string(To_test.of_txs ["A";"B";"C";"D";"E";"F";"G";"H";"I"]))

let test_equality_mtree () =
  Alcotest.(check mtree_testable) "same merkle tree" (To_test.of_txs ["A";"B";"C";"D"]) (To_test.of_txs ["A";"B";"C";"D"])

let absurd_equality_mtree () =
  Alcotest.(check  (neg mtree_testable)) "not same merkle tree, fail" (To_test.of_txs ["A";"B";"J";"D"]) (To_test.of_txs ["A";"B";"C";"D"])


let test_witness_empty_mtree () =
  Alcotest.(check_raises "empty merkle tree") (Failure "empty merkle tree") (fun () -> ignore (To_test.witness "A" Empty))

let test_witness_not_included () = 
  Alcotest.(check_raises "proof not found") (Failure "proof not found") (fun () -> ignore (To_test.witness "F" mtreeEx))

let test_witness_included () =
  Alcotest.(check proof_testable) "same proof tree" proof_included (To_test.witness "A" mtreeEx)

let test_proof_empty_mtree () =
  Alcotest.(check bool) "same value" false (To_test.proof "A" wtnEx Empty)
let test_proof_empty_wtn () = 
  Alcotest.(check bool) "same value" false (To_test.proof "A" [] mtreeEx)
let test_proof_included () = 
  Alcotest.(check bool) "same value" true (To_test.proof "A" wtnEx mtreeEx)
let test_proof_not_included () = 
  Alcotest.(check bool) "same value" false (To_test.proof "F" wtnEx mtreeEx)
let test_proof_bad_wtn () = 
  Alcotest.(check bool) "same value" false (To_test.proof "A" badWtnEx mtreeEx)

let () =
  let open Alcotest in
  run "Merkle tree with str/sha256 context"
    [
        ("Creating a merkle tree from a list of content",
          [
              test_case "Creating mtree from empty list" `Quick test_of_txs_empty;
              test_case "Creating mtree from list with odd length (5 elements)" `Quick test_of_txs_odd5;
              test_case "Creating mtree from list with odd length (9 elements)" `Quick test_of_txs_odd9;
              test_case "Creating mtree from list with even length" `Quick test_of_txs_even;
          ]
        );
        ("Testing equality between merkle trees",
        [
              test_case "Testing equality between two same mtree" `Quick test_equality_mtree;
              test_case "Testing the equality between two different mtree" `Quick absurd_equality_mtree;
        ]);
        ("The minimal merkle tree that can prove a given content",
          [
            test_case "Find the witness of a content in a empty mtree" `Quick test_witness_empty_mtree;
            test_case "Find the witness of a content not contained in the mtree" `Quick test_witness_not_included;
            test_case "Find the witness of a content contained in the mtree" `Quick test_witness_included;
          ]
              
        );
        ("Prove integrity of a value", [
              test_case "Prove someting on a empty mtree" `Quick test_proof_empty_mtree;
              test_case "Prove something with a empty witness" `Quick test_proof_empty_wtn;
              test_case "Prove a content not contained in the mtree" `Quick test_proof_not_included;
              test_case "Prove a content contained in the mtree" `Quick test_proof_included;
              test_case "Prove a content with a witness of another content" `Quick test_proof_bad_wtn;
        ]
        );
    ]