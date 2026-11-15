// Known gap (4.1, M7 Ruling H): jQuery `$(...).html(x)` as a sink is not reported. The 4.1 recall arm for it cost
// main-pass time with no hit on the fresh set, so it moved to 4.2; this file records the shape.
// jQuery: the fragment is written as markup.
$("#out").html(location.hash.slice(1));
