#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "jansson.h"

/**
 * Get the value from a key in a JSON string.
 * @param[in] root JSON string.
 * @param[out] value Buffer to store the JSON value.
 * @param[in] level The level of the JSON value in the JSON string.
 * @param[in] ... Keys.
 * @return NULL: Failed. others: JSON value.
 */
json_t *json_get_value(const json_t *root, json_t **value, int level, ...)
{
	json_t *r = (json_t *)root;
	json_t *v = NULL;
	va_list args;

	if (!root)
		return NULL;

	va_start(args, level);

	for (size_t i = 0; i != level; i++) {
		char *key = va_arg(args, char *);

		v = json_object_get(r, key);
		if (!v)
			return NULL;

		r = v;
	}

	*value = v;

	return *value;
}

/**
 * Set a value to a key in a JSON string.
 * @param[in] root JSON string.
 * @param[in] key The key to be set.
 * @param[in] value The JSON value to be set.
 * @param[in] level The level of the parent of the key in the JSON string.
 * @param[in] ... Keys.
 * @return true: Succeeded. false: Failed.
 */
bool json_set_value(const json_t *root,
		const char *key, json_t *value, int level, ...)
{
	json_t *r = (json_t *)root;
	va_list args;

	if (!root || !value)
		return false;

	va_start(args, level);

	for (size_t i = 0; i != level; i++) {
		char *k = va_arg(args, char *);
		json_t *v = NULL;

		v = json_object_get(r, k);
		if (!v)
			return false;

		r = v;
	}

	if (json_object_set(r, key, value) == -1)
		return false;

	return true;
}

int main(int argc, char *argv[])
{
	const char *json = "{\"root\": {\"first\": {\"name\": \"one\"}, "
				"\"second\": {\"name\": \"two\"}}}";
	const char *str = NULL;
	json_t *root = NULL;
	json_t *value = NULL;
	json_error_t error;
	char *new_json = NULL;

	root = json_loads(json, 0, &error);
	if (!root)
		return 1;

	if (!json_get_value(root, &value, 3, "root", "first", "name"))
		return 1;

	str = json_string_value(value);
	if (!str)
		return 1;

	printf("Original JSON: %s\n", json);
	printf("first name: %s\n", str);

	if (!json_set_value(root, "name",
			json_string("2"), 2, "root", "second"))
		return 1;

	new_json = json_dumps(root, 0);
	if (!new_json)
		return 1;

	printf("New JSON string: %s\n", new_json);
	free(new_json);
	new_json = NULL;

	return 0;
}
