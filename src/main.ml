open Merkle

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

let () = Printf.printf "Merkle tree library\n"