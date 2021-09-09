(** Library that represents Merkle tree data structure. *)

(** MTreeContext is a "context" module for a merkle tree which contains the data type of the nodes 
and a type for the cryptographic hash.*)
module type MTreeContext =
  sig
    (** The type of the data contained in merkle tree node. *)
    type data

    (** The type of the hash you will use. *)
    type digest

    (** [hash data] takes a [data] and returns his hash.*)
    val hash : data -> digest

    (** [concat_hashes h1 h2] takes [h1] and [h2] and returns the hash of the concatenation of [h1] ans [h2]. *)
    val concat_hashes : digest -> digest -> digest

    (** [equal h1 h2] tests if [h1] and [h2] are equal.*)
    val equal : digest -> digest -> bool

    (** [dig_to_string h] return a string form of the digest h*)
    val to_string : digest -> string
  end

(** Signature of the MerkleTree module. 
The merkle tree module is a functor parameterized by a context module.*)
module type MerkleTree =
  functor (Ctx : MTreeContext) ->
    sig
      (** the type of the merkle tree.  *)
      type t

      (** the type of the minimal merkle tree that can prove a certain content.  *)
      type proof

      (** [mtree_of_txs txs] takes a list of content [txs] and build a merkle tree from it 
          if the length of the list is even, the tree will be pretty balanced, not if its odd.*)
      
      (*Exemple : 

              abcd              abcdee
            ab    cd      ->  abcd      
          a   b  c   d      ab   cd   ee
                          a   b c  d e  e
      *)
      val mtree_of_txs : Ctx.data list -> t

      (** [witness data mtree] takes a content, a merkle tree, 
          and returns the minimal merkle tree that can prove the given content.*)
      val witness : Ctx.data -> t -> proof

      (** [proof data witness mtree] takes a content, a "witness" which is a minimal merkle tree
          and the entire merkle tree, and verify that the content is included in the 
          entire merkle tree thanks to the witness. *)
      val proof : Ctx.data -> proof -> t -> bool

      (** [equal mtree mtree'] takes two merkle trees and verify if they are equal or not. *)
      val equal : t -> t -> bool

      (** [to_string mtree] takes a mtree and returns a readable string form of the mtree *)
      val to_string : t -> string
    end

module MerkleTree :
  functor (Ctx : MTreeContext) ->
    sig
      type mtree = Leaf of Ctx.digest | Node of Ctx.digest * mtree * mtree
      type t = Empty | Mtree of mtree

      (** the type direction represent in which order i have to concat hashes 
          when i make a proof of a content, because the witness is represented as a list 
          in this implementation.*)
      type direction = L | R
      type proof = (Ctx.digest * direction) list
      val get_hash : mtree -> Ctx.digest
      val mtree_of_txs : Ctx.data list -> t
      val witness : Ctx.data -> t -> proof
      val proof : Ctx.data -> proof -> t -> bool
      val equal : t -> t -> bool
      val to_string : t -> string
    end