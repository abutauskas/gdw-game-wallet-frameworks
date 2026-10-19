## Editor plugin entry point. The wallet helpers are plain RefCounted classes
## (Gdw, GdwKey, GdwUtil) so they work in exported games without the editor
## plugin; this script only makes the addon toggleable in the editor.
##
## SPDX-License-Identifier: CC-BY-4.0
@tool
extends EditorPlugin


func _enter_tree() -> void:
	# Nothing to register: the classes are global via class_name.
	pass
