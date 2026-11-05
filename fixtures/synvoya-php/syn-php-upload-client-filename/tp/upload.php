<?php
$target = __DIR__ . '/uploads/' . $_FILES['avatar']['name'];
move_uploaded_file($_FILES['avatar']['tmp_name'], $target);
class AvatarController {
    public function store(Request $request) {
        $file = $request->file('avatar');
        $name = time() . '.' . $file->getClientOriginalExtension();
        $file->move(public_path('avatars'), $name);
    }
}
