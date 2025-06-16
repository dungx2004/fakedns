#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>
#include "config.h"
#include "fakedns.h"

// Convert domain name dạng người đọc sang dạng QNAME
size_t dname_to_qname(char *dname, unsigned char *qname) {
	memset(qname, 0, MAX_DNS_QNAME_LEN);
	char label_len[2] = {'\0', '\0'};
	size_t qname_len = 0;

	char *label = strtok(dname, ".");
	while (label != NULL) {
		label_len[0] = strlen(label);
		strcat((char *)qname, label_len);
		strcat((char *)qname, label);
		label = strtok(NULL, ".");
		qname_len += 1 + label_len[0];
	}
	qname_len++;
	return qname_len;
}

char *dup_str(const char *s) {
	if (!s) return NULL;
	char *d = malloc(strlen(s) + 1);
	return d ? strcpy(d, s) : NULL;
}

static const char *node_str(yaml_document_t *doc, yaml_node_t *node) {
	return (const char *)node->data.scalar.value;
}

int config_read(struct config *conf) {
	memset(conf, 0, sizeof(*conf));

	FILE *file = fopen(CONFIG_FILE, "r");
	if (!file) {
		perror("fopen");
		return -1;
	}

	yaml_parser_t parser;
	yaml_document_t doc;
	if (!yaml_parser_initialize(&parser)) {
		fprintf(stderr, "Failed to init YAML parser\n");
		fclose(file);
		return -1;
	}
	yaml_parser_set_input_file(&parser, file);

	if (!yaml_parser_load(&parser, &doc)) {
		fprintf(stderr, "Failed to load YAML document\n");
		yaml_parser_delete(&parser);
		fclose(file);
		return -1;
	}

	yaml_node_t *root = yaml_document_get_root_node(&doc);
	if (!root || root->type != YAML_MAPPING_NODE) {
		fprintf(stderr, "YAML root is not a mapping\n");
		goto error;
	}

	for (yaml_node_pair_t *pair = root->data.mapping.pairs.start;
			pair < root->data.mapping.pairs.top; ++pair) {
		yaml_node_t *key = yaml_document_get_node(&doc, pair->key);
		yaml_node_t *val = yaml_document_get_node(&doc, pair->value);
		const char *k = node_str(&doc, key);

		if (strcmp(k, "interface") == 0 && val->type == YAML_SCALAR_NODE) {
			conf->interface = strdup(node_str(&doc, val));
		}
		else if (strcmp(k, "fake_ipv4") == 0 && val->type == YAML_SCALAR_NODE) {
			conf->fake_ipv4 = strdup(node_str(&doc, val));
		}
		else if (strcmp(k, "fake_ipv6") == 0 && val->type == YAML_SCALAR_NODE) {
			conf->fake_ipv6 = strdup(node_str(&doc, val));
		}
		else if (strcmp(k, "logfile") == 0 && val->type == YAML_SCALAR_NODE) {
			conf->logfile = strdup(node_str(&doc, val));
		}
		else if (strcmp(k, "blacklist") == 0 && val->type == YAML_MAPPING_NODE) {
			// Traverse blacklist mapping
			for (yaml_node_pair_t *bp = val->data.mapping.pairs.start;
					bp < val->data.mapping.pairs.top; ++bp) {
				yaml_node_t *bkey = yaml_document_get_node(&doc, bp->key);
				yaml_node_t *bval = yaml_document_get_node(&doc, bp->value);
				const char *group = node_str(&doc, bkey);

				// bval must be a sequence of domains
				if (bval->type != YAML_SEQUENCE_NODE) continue;

				int is_default = (strcmp(group, "default") == 0);
				int idx = conf->ip_count;  // for non-default

				if (!is_default) {
					conf->ips[idx] = strdup(group);
					conf->lists[idx].qname_count = 0;
				}

				// iterate domains
				for (yaml_node_item_t *it = bval->data.sequence.items.start;
						it < bval->data.sequence.items.top; ++it) {
					yaml_node_t *dnode = yaml_document_get_node(&doc, *it);
					if (dnode->type != YAML_SCALAR_NODE) continue;
					const char *domain = node_str(&doc, dnode);
					unsigned char *qname = malloc(MAX_DNS_QNAME_LEN);
					dname_to_qname((char *)domain, qname);

					if (is_default) {
						int di = conf->default_list.qname_count++;
						conf->default_list.qnames[di] = qname;
					} else {
						int di = conf->lists[idx].qname_count++;
						conf->lists[idx].qnames[di] = qname;
					}
				}

				if (!is_default) {
					conf->ip_count++;
				}
			}
		}
	}

	yaml_document_delete(&doc);
	yaml_parser_delete(&parser);
	fclose(file);
	return 0;

error:
	yaml_document_delete(&doc);
	yaml_parser_delete(&parser);
	fclose(file);
	return -1;
}


// Xoá cấu trúc config
void config_free(struct config *conf) {
	free(conf->interface);
	free(conf->fake_ipv4);
	free(conf->fake_ipv6);
	free(conf->logfile);

	for (int i = 0; i < conf->ip_count; i++) {
		free(conf->ips[i]);
		for (int j = 0; j < conf->lists[i].qname_count; j++) {
			free(conf->lists[i].qnames[j]);
		}
	}

	for (int i = 0; i < conf->default_list.qname_count; i++) {
		free(conf->default_list.qnames[i]);
	}
}
