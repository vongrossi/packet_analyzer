#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAX_PACKET_SIZE 1500  // Tamanho máximo do pacote em bytes

void parse_packet(const uint8_t *packet, size_t length) {
    printf("### Pacote recebido ###\n");

    // Ethernet Header
    printf("Ethernet Header:\n");
    printf("  MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
    printf("  MAC origem: %02x:%02x:%02x:%02x:%02x:%02x\n",
           packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    printf("  Tipo: 0x%02x%02x\n", packet[12], packet[13]);

    // IP Header
    printf("\nIP Header:\n");
    printf("  Versão: %d\n", (packet[14] >> 4));
    printf("  Tamanho do cabeçalho: %d bytes\n", (packet[14] & 0x0F) * 4);
    printf("  Total Length: %d bytes\n", (packet[16] << 8) | packet[17]);
    printf("  TTL: %d\n", packet[22]);
    printf("  Protocolo: %d (TCP)\n", packet[23]);
    printf("  IP Origem: %d.%d.%d.%d\n", packet[26], packet[27], packet[28], packet[29]);
    printf("  IP Destino: %d.%d.%d.%d\n", packet[30], packet[31], packet[32], packet[33]);

    // TCP Header
    printf("\nTCP Header:\n");
    printf("  Porta Origem: %d\n", (packet[34] << 8) | packet[35]);
    printf("  Porta Destino: %d\n", (packet[36] << 8) | packet[37]);
    printf("  Número de sequência: %u\n", (packet[38] << 24) | (packet[39] << 16) | (packet[40] << 8) | packet[41]);
    printf("  Número de reconhecimento (ACK): %u\n", (packet[42] << 24) | (packet[43] << 16) | (packet[44] << 8) | packet[45]);

    uint8_t flags = packet[47];
    printf("  Flags: 0x%02x\n", flags);
    if (flags & 0x08) printf("    PSH\n");
    if (flags & 0x10) printf("    ACK\n");
    if (flags & 0x01) printf("    FIN\n");
    if (flags & 0x02) printf("    SYN\n");
    if (flags & 0x04) printf("    RST\n");
    if (flags & 0x20) printf("    URG\n");
    if (flags & 0x40) printf("    ECE\n");
    if (flags & 0x80) printf("    CWR\n");

    // Application Layer (if any)
    printf("\nApplication Layer:\n");
    if (length > 54) {
        printf("  Dados: ");
        for (size_t i = 54; i < length; i++) {
            // Verifica se o byte é imprimível
            if (packet[i] >= 32 && packet[i] <= 126) {
                printf("%c", packet[i]); // Caracter imprimível
            } else {
                printf("."); // Substitui caracteres não imprimíveis
            }
        }
        printf("\n");
    } else {
        printf("  Sem dados na camada de aplicação.\n");
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <arquivo_txt>\n", argv[0]);
        return 1;
    }

    // Abrir o arquivo para leitura
    FILE *file = fopen(argv[1], "r");
    if (!file) {
        perror("Erro ao abrir o arquivo");
        return 1;
    }

    uint8_t packet[MAX_PACKET_SIZE];
    size_t packet_length = 0;

    // Ler o conteúdo do arquivo e converter hex para bytes
    char hex_byte[3];
    while (fscanf(file, "%2s", hex_byte) == 1) {
        if (packet_length >= MAX_PACKET_SIZE) {
            fprintf(stderr, "Tamanho do pacote excede o limite.\n");
            fclose(file);
            return 1;
        }
        packet[packet_length++] = (uint8_t)strtol(hex_byte, NULL, 16);
    }
    fclose(file);

    // Analisar o pacote
    parse_packet(packet, packet_length);

    return 0;
}
