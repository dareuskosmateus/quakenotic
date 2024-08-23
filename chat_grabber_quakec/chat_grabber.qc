#include "char_grabber.qh"

AUTOCVAR(g_chat_grabber, int, 0, "Enable chat message grabber");
AUTOCVAR(chat_dest_udp, string, "", "UDP protocoled socket destination for caught chat messages");

REGISTER_MUTATOR(chat_grabber, autocvar_chat_dest_udp);

MUTATOR_HOOKFUNCTION(chat_grabber, BuildMutatorsPrettyString) {
    M_ARGV(0, string) = strcat(M_ARGV(0, string), ", Chat grabber");
}

MUTATOR_HOOKFUNCTION(chat_grabber, BuildMutatorsString) {
    M_ARGV(0, string) = strcat(M_ARGV(0, string), ":mod");
}

MUTATOR_HOOKFUNCTION(chat_grabber, PreFormatMessage) {
    entity client = M_ARGV(0, entity);
    string msg = M_ARGV(1, string);

    string nickname = GetCallerName(clientid);

    string formatted = sprintf("#%s <%s>: %s", client.playerid, nickname, msg);
    sendto(formatted);
}

void sendto(string msg) {
    //additional stuff to be added here
    localcmd(sprintf("packet %s %s", chat_dest_udp, msg);
    return;
}
