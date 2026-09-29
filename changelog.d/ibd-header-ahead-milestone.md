Added

- **Header sync runs ahead of the block body during IBD.** Two outbound
  peers must return the same header prefix before it can open the milestone
  script skip. One peer still fills the ordered body window so IBD connects.
  The ordered body window stays at
  64k headers; later blocks are filled from headers already stored. A peer
  with `getheaders` outstanding is not given new block `getdata`. Restart
  resumes from `header.adopt` when that hash is still in `header.body`.
