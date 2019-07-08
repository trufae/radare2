/* radare - LGPL - Copyright 2009-2020 - pancake, h4ng3r */

#include <r_types.h>
#include <r_util.h>
#include "dex.h"

char* r_bin_dex_get_version(RBinDexObj *bin) {
	r_return_val_if_fail (bin, NULL);
	char* version = calloc (1, 8);
	if (version) {
		r_buf_read_at (bin->b, 4, (ut8*)version, 3);
		return version;
	}
	return NULL;
}

void r_bin_dex_free(RBinDexObj *dex) {
	struct dex_header_t *dexhdr = &dex->header;
	if (dex->cal_strings) {
		size_t i;
		for (i = 0; i < dexhdr->strings_size; i++) {
			free (dex->cal_strings[i]);
		}
	}
	free (dex->cal_strings);
	free (dex);
}

static char *getstr(RBinDexObj *bin, int idx) {
	ut8 buf[6];
	ut64 len;
	int uleblen;
	// null terminate the buf wtf
	if (!bin || idx < 0 || idx >= bin->header.strings_size || !bin->strings) {
		return NULL;
	}
	if (bin->strings[idx] >= bin->size) {
		return NULL;
	}
	if (r_buf_read_at (bin->b, bin->strings[idx], buf, sizeof (buf)) < 1) {
		return NULL;
	}
	r_buf_write_at (bin->b, r_buf_size (bin->b) - 1, (ut8 *)"\x00", 1);
	uleblen = r_uleb128 (buf, sizeof (buf), &len) - buf;
	if (!uleblen || uleblen >= bin->size) {
		return NULL;
	}
	if (!len || len >= bin->size) {
		return NULL;
	}
	if (bin->strings[idx] + uleblen >= bin->strings[idx] + bin->header.strings_size) {
		return NULL;
	}
	ut8 *ptr = R_NEWS (ut8, len + 1);
	if (ptr) {
		r_buf_read_at (bin->b, bin->strings[idx] + uleblen, ptr, len + 1);
		ptr[len] = 0;
		if (len != r_utf8_strlen (ptr)) {
			// eprintf ("WARNING: Invalid string for index %d\n", idx);
			return NULL;
		}
	}
	return (char *)ptr;
}

static const char *visibility(int n) {
	switch (n) {
#if 0
	case kDexVisibilityBuild:
		return "build";
	case kDexVisibilityRuntime:
		return "runtime";
	case kDexVisibilitySystem:
		return "system";
#endif
	case kDexAnnotationByte:
	case kDexAnnotationShort:
		return "short";
	case kDexAnnotationChar:
		return "char";
	case kDexAnnotationInt:
		return "int";
	case kDexAnnotationLong:
		return "long";
	case kDexAnnotationFloat:
		return "float";
	case kDexAnnotationDouble:
		return "double";
	case kDexAnnotationString:
		return "string";
	case kDexAnnotationType:
		return "type";
	case kDexAnnotationField:
		return "field";
	case kDexAnnotationMethod:
		return "method";
	case kDexAnnotationEnum:
		return "enum";
	case kDexAnnotationArray:
		return "array";
	case kDexAnnotationAnnotation:
		return "annotation";
	case kDexAnnotationNull:
		return "null";
	case kDexAnnotationBoolean:
		return "bool";
	}
	return "?";
}

static const char *className (RBinDexObj *bin, int idx) {
	DexType *dt = &bin->types[idx];
	char *name = getstr (bin, dt->descriptor_id); // bin->classes[i].name_id);
	return name;
}

static void parseValue(RBinDexObj *dex) {
	ut8 argAndType = r_buf_read8 (dex->b);
	int type = (argAndType & 0x1f);
	int arg = (argAndType & 0xe0) >> 5;
	int size = arg + 1;

	switch (type) {
	case R_DEX_ENCVAL_BYTE:
		eprintf ("BYTE 0x%08x\n", r_buf_read8 (dex->b));
		break;
	case R_DEX_ENCVAL_SHORT:
		eprintf ("SHORT\n");
		break;
	case R_DEX_ENCVAL_CHAR:
		eprintf ("CHAR\n");
		break;
	case R_DEX_ENCVAL_INT:
		eprintf ("INT\n");
		break;
	case R_DEX_ENCVAL_LONG:
		eprintf ("LONG\n");
		break;
	case R_DEX_ENCVAL_FLOAT:
		eprintf ("FLOAT\n");
		break;
	case R_DEX_ENCVAL_DOUBLE:
		eprintf ("DOUBLE\n");
		break;
	case R_DEX_ENCVAL_STRING:
		eprintf ("STRING\n");
		break;
	case R_DEX_ENCVAL_TYPE:
		eprintf ("TYPE\n");
		break;
	case R_DEX_ENCVAL_FIELD:
		eprintf ("FIELD\n");
		break;
	case R_DEX_ENCVAL_ENUM:
		eprintf ("ENUM\n");
		break;
	case R_DEX_ENCVAL_METHOD:
		eprintf ("METHOD\n");
		break;
	case R_DEX_ENCVAL_ARRAY:
		eprintf ("ARRAY\n");
		break;
	case R_DEX_ENCVAL_ANNOTATION:
		eprintf ("ANNOTATION\n");
		break;
	case R_DEX_ENCVAL_NULL:
		eprintf ("NULL\n");
		break;
	case R_DEX_ENCVAL_BOOLEAN:
		eprintf ("BOOLEAN\n");
		break;
	}
}

static void readAnnotation(RBinDexObj *dex, bool readVisibility) {
	ut64 typeIndex, typeSize, stringIndex, i;
	RBuffer *buf = dex->b;
	if (readVisibility) {
		ut8 b = r_buf_read8 (buf);
		switch (b) {
		case R_DEX_VISIBILITY_BUILD:
			eprintf ("Visibility: BUILD\n");
			break;
		case R_DEX_VISIBILITY_RUNTIME:
			eprintf ("Visibility: RUNTIME\n");
			break;
		case R_DEX_VISIBILITY_SYSTEM:
			eprintf ("Visibility: SYSTEM\n");
			break;
		default:
			eprintf ("Visibility: UNKNOWN (0x%02x)\n", b);
			break;
		}
	}
	typeIndex = -1;
	typeSize = -1;
	(void)r_buf_uleb128 (buf, &typeIndex);
	(void)r_buf_uleb128 (buf, &typeSize);
	if (typeIndex < 0 || typeSize < 0) {
		return;
	}
	if (typeIndex > 10000 || typeSize > 1000) {
		return;
	}
	char *typeString = getstr (dex, typeIndex);
	eprintf ("TypeSize: %d %d (%s)\n", (int)typeIndex, (int)typeSize, typeString);
	for (i = 0; i < typeSize; i++) {
		r_buf_uleb128 (buf, &stringIndex);
		const char *name = getstr (dex, stringIndex);
		eprintf ("ITEM %d %s\n", (int)stringIndex, name);
		parseValue (dex);
	}
}

static void readAnnotationSet(RBinDexObj *dex, ut64 addr) {
	r_buf_seek (dex->b, addr, R_BUF_SET);
	ut32 i, size = r_buf_read_le32 (dex->b);
	addr += sizeof (ut32);
	for (i = 0; i < size; i++) {
		r_buf_seek (dex->b, addr + (i * sizeof (ut32)), R_BUF_SET);
		ut32 at = r_buf_read_le32 (dex->b);
		r_buf_seek (dex->b, at, R_BUF_SET);
		readAnnotation (dex, true);
	}
	r_buf_seek (dex->b, addr + (i * sizeof (ut32)), R_BUF_SET);
}

#define FAIL(x) { eprintf(x"\n"); goto fail; }

RBinDexObj *r_bin_dex_new_buf(RBuffer *buf) {
	r_return_val_if_fail (buf, NULL);
	RBinDexObj *bin = R_NEW0 (RBinDexObj);
	int i;
	struct dex_header_t *dexhdr;
	if (!bin) {
		goto fail;
	}
	bin->size = r_buf_size (buf);
	bin->b = r_buf_ref (buf);
	/* header */
	if (bin->size < sizeof (struct dex_header_t)) {
		goto fail;
	}
	dexhdr = &bin->header;

	if (bin->size < 112) {
		goto fail;
	}

	r_buf_seek (bin->b, 0, R_BUF_SET);
	r_buf_read (bin->b, (ut8 *)&dexhdr->magic, 8);
	dexhdr->checksum = r_buf_read_le32 (bin->b);
	r_buf_read (bin->b, (ut8 *)&dexhdr->signature, 20);
	dexhdr->size = r_buf_read_le32 (bin->b);
	dexhdr->header_size = r_buf_read_le32 (bin->b);
	dexhdr->endian = r_buf_read_le32 (bin->b);
	// TODO: this offsets and size will be used for checking,
	// so they should be checked. Check overlap, < 0, > bin.size
	dexhdr->linksection_size = r_buf_read_le32 (bin->b);
	dexhdr->linksection_offset = r_buf_read_le32 (bin->b);
	dexhdr->map_offset = r_buf_read_le32 (bin->b);
	dexhdr->strings_size = r_buf_read_le32 (bin->b);
	dexhdr->strings_offset = r_buf_read_le32 (bin->b);
	dexhdr->types_size = r_buf_read_le32 (bin->b);
	dexhdr->types_offset = r_buf_read_le32 (bin->b);
	dexhdr->prototypes_size = r_buf_read_le32 (bin->b);
	dexhdr->prototypes_offset = r_buf_read_le32 (bin->b);
	dexhdr->fields_size = r_buf_read_le32 (bin->b);
	dexhdr->fields_offset = r_buf_read_le32 (bin->b);
	dexhdr->method_size = r_buf_read_le32 (bin->b);
	dexhdr->method_offset = r_buf_read_le32 (bin->b);
	dexhdr->class_size = r_buf_read_le32 (bin->b);
	dexhdr->class_offset = r_buf_read_le32 (bin->b);
	dexhdr->data_size = r_buf_read_le32 (bin->b);
	dexhdr->data_offset = r_buf_read_le32 (bin->b);

	/* strings */
	#define STRINGS_SIZE ((dexhdr->strings_size + 1) * sizeof (ut32))
	if (dexhdr->strings_size > bin->size) {
		goto fail;
	}
	bin->strings = R_NEWS0 (ut32, dexhdr->strings_size + 1);
	if (!bin->strings) {
		goto fail;
	}
	r_buf_read_at (bin->b, dexhdr->strings_offset, (ut8*)bin->strings, dexhdr->strings_size * sizeof (ut32));
	// TODO: this is unnecessary on Big endian machines
	for (i = 0; i < dexhdr->strings_size; i++) {
		ut64 offset = dexhdr->strings_offset + (i * sizeof (ut32));
		if (offset + 4 > bin->size) {
			break;
		}
		bin->strings[i] = r_read_le32 (&bin->strings[i]);
	}
	/* classes */
	// TODO: not sure about if that is needed
	size_t classes_size = dexhdr->class_size * DEX_CLASS_SIZE;
	if (dexhdr->class_offset + classes_size >= bin->size) {
		if (dexhdr->class_offset < bin->size) {
			classes_size = bin->size - dexhdr->class_offset;
		} else {
			classes_size = 0;
		}
	}

	dexhdr->class_size = classes_size / DEX_CLASS_SIZE;
	bin->classes = (struct dex_class_t *) calloc (dexhdr->class_size + 1,
		sizeof (struct dex_class_t));
	for (i = 0; i < dexhdr->class_size; i++) {
		ut64 offset = dexhdr->class_offset + i * DEX_CLASS_SIZE;
		if (offset + 32 > bin->size) {
			free (bin->strings);
			free (bin->classes);
			goto fail;
		}
		r_buf_seek (bin->b, offset, R_BUF_SET);
		bin->classes[i].class_id = r_buf_read_le32 (bin->b);
		bin->classes[i].access_flags = r_buf_read_le32 (bin->b);
		bin->classes[i].super_class = r_buf_read_le32 (bin->b);
		bin->classes[i].interfaces_offset = r_buf_read_le32 (bin->b);
		bin->classes[i].source_file = r_buf_read_le32 (bin->b);
		bin->classes[i].anotations_offset = r_buf_read_le32 (bin->b);
		bin->classes[i].class_data_offset = r_buf_read_le32 (bin->b);
		bin->classes[i].static_values_offset = r_buf_read_le32 (bin->b);
	}

	/* methods */
	size_t methods_size = dexhdr->method_size * sizeof (struct dex_method_t);
	if (dexhdr->method_offset + methods_size >= bin->size) {
		if (dexhdr->method_offset < bin->size) {
			methods_size = bin->size - dexhdr->method_offset;
		} else {
			methods_size = 0;
		}
	}
	dexhdr->method_size = methods_size / sizeof (struct dex_method_t);
	bin->methods = (struct dex_method_t *) calloc (methods_size + 1, 1);
	for (i = 0; i < dexhdr->method_size; i++) {
		ut64 offset = dexhdr->method_offset + i * sizeof (struct dex_method_t);
		if (offset + 8 > bin->size) {
			free (bin->strings);
			free (bin->classes);
			free (bin->methods);
			goto fail;
		}
		r_buf_seek (bin->b, offset, R_BUF_SET);
		bin->methods[i].class_id = r_buf_read_le16 (bin->b);
		bin->methods[i].proto_id = r_buf_read_le16 (bin->b);
		bin->methods[i].name_id = r_buf_read_le32 (bin->b);
	}

	/* types */
	size_t types_size = dexhdr->types_size * sizeof (struct dex_type_t);
	if (dexhdr->types_offset + types_size >= bin->size) {
		types_size = bin->size - dexhdr->types_offset;
	}
	dexhdr->types_size = types_size / sizeof (struct dex_type_t);
	bin->types = (struct dex_type_t *) calloc (types_size + 1, 1);
	for (i = 0; i < dexhdr->types_size; i++) {
		ut64 offset = dexhdr->types_offset + i * sizeof (struct dex_type_t);
		if (offset + 4 > bin->size) {
			free (bin->strings);
			free (bin->classes);
			free (bin->methods);
			free (bin->types);
			goto fail;
		}
		bin->types[i].descriptor_id = r_buf_read_le32_at (bin->b, offset);
	}

	/* fields */
	size_t fields_size = dexhdr->fields_size * sizeof (struct dex_field_t);
	if (dexhdr->fields_offset + fields_size >= bin->size) {
		if (bin->size > dexhdr->fields_offset) {
			fields_size = bin->size - dexhdr->fields_offset;
		} else {
			fields_size = 0;
		}
	}
	dexhdr->fields_size = fields_size / sizeof (struct dex_field_t);
	bin->fields = (struct dex_field_t *) calloc (fields_size + 1, 1);
	for (i = 0; i < dexhdr->fields_size; i++) {
		ut64 offset = dexhdr->fields_offset + i * sizeof (struct dex_field_t);
		if (offset + 8 > bin->size) {
			free (bin->strings);
			free (bin->classes);
			free (bin->methods);
			free (bin->types);
			free (bin->fields);
			goto fail;
		}
		r_buf_seek (bin->b, offset, R_BUF_SET);
		bin->fields[i].class_id = r_buf_read_le16 (bin->b);
		bin->fields[i].type_id = r_buf_read_le16 (bin->b);
		bin->fields[i].name_id = r_buf_read_le32 (bin->b);
	}

	/* proto */
	size_t protos_size = dexhdr->prototypes_size * sizeof (struct dex_proto_t);
	if (dexhdr->prototypes_offset + protos_size >= bin->size) {
		if (bin->size > dexhdr->prototypes_offset) {
			protos_size = bin->size - dexhdr->prototypes_offset;
		} else {
			protos_size = 0;
		}
	}
	dexhdr->prototypes_size = protos_size / sizeof (struct dex_proto_t);
	bin->protos = (struct dex_proto_t *) calloc (protos_size + 1, 1);
	for (i = 0; i < dexhdr->prototypes_size; i++) {
		ut64 offset = dexhdr->prototypes_offset + i * sizeof (struct dex_proto_t);
		if (offset + 12 > bin->size) {
			free (bin->strings);
			free (bin->classes);
			free (bin->methods);
			free (bin->types);
			free (bin->fields);
			free (bin->protos);
			goto fail;
		}
		r_buf_seek (bin->b, offset, R_BUF_SET);
		bin->protos[i].shorty_id = r_buf_read_le32 (bin->b);
		bin->protos[i].return_type_id = r_buf_read_le32 (bin->b);
		bin->protos[i].parameters_off = r_buf_read_le32 (bin->b);
	}
	eprintf ("Parse annotations\n");
	for (i = 0; i < dexhdr->class_size; i++) {
		ut64 at = bin->classes[i].anotations_offset;
		if (!at || at == UT64_MAX) {
			continue;
		}
		int j;
		const char *cn = className (bin, bin->classes[i].class_id);
		r_buf_seek (bin->b, at, R_BUF_SET);
		ut32 classAnnotationsOffset = r_buf_read_le32 (bin->b);
		ut32 fieldsCount = r_buf_read_le32 (bin->b);
		ut32 annotatedMethodsCount = r_buf_read_le32 (bin->b);
		ut32 annotatedParametersCount = r_buf_read_le32 (bin->b);
		eprintf ("0x%08"PFMT64x"  annotationOffset\n", at);
		eprintf ("0x%08"PFMT64x"  classAnnotationOffset\n", (ut64)classAnnotationsOffset);
		eprintf ("            className %s\n", cn);
		eprintf ("            fieldsCount %d\n", fieldsCount);
		eprintf ("            annotatedMethodCount  %d\n", annotatedMethodsCount);
		eprintf ("            annotatedParametersCount  %d\n", annotatedParametersCount);

		ut64 addr = at + (4 * sizeof (ut32));
		if (classAnnotationsOffset > 0) {
			ut64 cur = r_buf_seek (bin->b, 0, R_BUF_CUR);
			readAnnotationSet (bin, classAnnotationsOffset);
			r_buf_seek (bin->b, cur, R_BUF_SET);
		}
		for (j = 0; j < fieldsCount; j++) {
			ut32 fieldId = r_buf_read_le32 (bin->b);
			ut32 annotationsOffset = r_buf_read_le32 (bin->b);
			ut64 cur = r_buf_seek (bin->b, 0, R_BUF_CUR);
			eprintf ("        Annotations for fieldId %d:\n", fieldId);
			readAnnotationSet (bin, annotationsOffset);
			r_buf_seek (bin->b, cur, R_BUF_SET);
		}
		for (j = 0; j < annotatedMethodsCount ; j++) {
			ut32 methodId = r_buf_read_le32 (bin->b);
			ut32 annotationsOffset = r_buf_read_le32 (bin->b);
			ut64 cur = r_buf_seek (bin->b, 0, R_BUF_CUR);
			eprintf ("        Annotations for methodId %d:\n", methodId);
			readAnnotationSet (bin, annotationsOffset);
			r_buf_seek (bin->b, cur, R_BUF_SET);
		}
		for (j = 0; j < annotatedParametersCount ; j++) {
			ut32 methodId = r_buf_read_le32 (bin->b);
			ut32 annotationsOffset = r_buf_read_le32 (bin->b);
			ut32 size = r_buf_read_le32 (bin->b);
int k;
			for (k = 0; k < size ; k++) {
				ut32 paramIndex = r_buf_read_le32 (bin->b);
				ut64 cur = r_buf_seek (bin->b, 0, R_BUF_CUR);
				eprintf ("        Annotations for methodId %d + paramIndex:\n", methodId, paramIndex);
				readAnnotationSet (bin, annotationsOffset);
				r_buf_seek (bin->b, cur, R_BUF_SET);
			}
		}
	}

	return bin;
fail:
	if (bin) {
		r_buf_free (bin->b);
		free (bin);
	}
	return NULL;
}
