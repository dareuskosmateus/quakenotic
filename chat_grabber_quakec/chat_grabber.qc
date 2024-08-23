AUTOCVAR(g_chat_grabber, int, 0, "Enable chat message grabber");
AUTOCVAR(chat_dest_udp, string, "", "UDP protocoled socket destination for caught chat messages");

REGISTER_MUTATOR(chat_grabber, autocvar_g_chat_grabber);

void sendto(string msg);

MUTATOR_HOOKFUNCTION(chat_grabber, BuildMutatorsPrettyString) {
    M_ARGV(0, string) = strcat(M_ARGV(0, string), ", Chat grabber");
}

MUTATOR_HOOKFUNCTION(chat_grabber, BuildMutatorsString) {
    M_ARGV(0, string) = strcat(M_ARGV(0, string), ":mod");
}

MUTATOR_HOOKFUNCTION(chat_grabber, PreFormatMessage) {
    print("Hook for PreFormatMessage called\n");
    entity client = M_ARGV(0, entity);
    string msg = strdecolorize(M_ARGV(1, string));

    string nickname = strdecolorize(GetCallerName(client));

    string formatted = sprintf("#%d <%s>: %s", client.playerid, nickname, msg);
    sendto(formatted);
}

void sendto(string msg) {
    //print("Sendto called\n");
    //additional stuff to be added here
    string cmd = sprintf("packet %s \"%s\"\n", autocvar_chat_dest_udp, msg);
    //print(cmd);
    localcmd(cmd);
    return;
}

void GenericCommand_discordsay(float request, float argc, string msg) {
    //print("discordsay called\n")
    //print(sprintf("%s\n"), msg);
    //print(sprintf("%s %s \n"), argv(0), argv(1), argv(2));
    switch(request) {
        case CMD_REQUEST_COMMAND:
            PrintToChatAll(argv(1)); //make it so it only says the contents of the message
            return;

        default:
        case CMD_REQUEST_USAGE:
            LOG_INFO("Usage: ", GetProgramCommandPrefix(), " discordsay MESSAGE");
            return;
    }
}

GENERIC_COMMAND(discordsay, "Send a message from discord to game chat", false) {
    GenericCommand_discordsay(request, arguments, command);
}
