//Название: Модуль виртуальной точки доступа
//Дата создания программы:02.06.2013
//Номер версии:1.0
//Дата последней модификации: 12.07.2013

class Vap : public Element {
public:
  Vap();
  ~Vap();

  // из библиотек программы Click
  const char *class_name() const	{ return "Vap"; }
  const char *port_count() const  { return "2/4"; }
  const char *processing() const  { return PUSH; }
  int initialize(ErrorHandler *); // initialize element
  int configure(Vector<String> &, ErrorHandler *);
  void add_handlers();
  void run_timer(Timer *timer);
  void push(int, Packet *);


  class VapagentStationState {
    public:
      EtherAddress _vap_bssid;
      IPAddress _sta_ip_addr_v4; // При необходимости можно поменять на ip v6
      Vector<String> _vap_ssids;
  };

  enum relation_t {
    EQUALS = 0,
    GREATER_THAN = 1,
    LESSER_THAN = 2,
  };

  class Subscription {
    public:
        long subscription_id;
        EtherAddress sta_addr;
        String statistic;
        relation_t rel;
        double val;
  };

  // Методы для отсылки и приема
  // 802.11 управляющих сообщений
  void recv_probe_request (Packet *p);
  void send_beacon (EtherAddress dst, EtherAddress bssid, String my_ssid, bool probe);
  void recv_assoc_request (Packet *p);
  void send_assoc_response (EtherAddress, uint16_t status, uint16_t associd);
  void recv_open_auth_request (Packet *p);
  void send_open_auth_response (EtherAddress dst, uint16_t seq, uint16_t status);
  Packet* wifi_encap (Packet *p, EtherAddress bssid);

  // Методы для работы с драйверами маршрутизации
  void add_subscription (long subscription_id, EtherAddress addr, String statistic, relation_t r, double val);
  void clear_subscriptions ();

  // Методы для добавления удаления вирт. ТД
  int add_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> sta_ssid);
  int set_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> vap_ssid);
  int remove_vap (EtherAddress sta_mac);

  // методы для обработчиков
  static String read_handler(Element *e, void *user_data);
  static int write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh);

  enum {
    handler_view_mapping_table,
    handler_num_slots,
    handler_add_vap,
    handler_set_vap,
    handler_rxstat,
    handler_remove_vap,
    handler_channel,
    handler_interval,
    handler_subscriptions,
    handler_debug,
    handler_probe_response,
    handler_probe_request, 
    handler_report_mean, 
    handler_update_signal_strength,
    handler_signal_strength_offset,
  };

  // Структура для статистики
  class StationStats {
  public:
    int _rate;
    int _noise;
    int _signal;

    int _packets;
    Timestamp _last_received;

    StationStats() {
      memset(this, 0, sizeof(*this));
    }
  };

  HashTable<EtherAddress, VapagentStationState> _sta_mapping_table;
  HashTable<EtherAddress, Timestamp> _mean_table;

  // Для статистики
  double _mean;
  double _num_mean;
  double _m2; // for estimated variance
  int _signal_offset;

  // Для сохранения статистики по клиентам
  HashTable<EtherAddress, StationStats> _rx_stats;

  int _interval_ms; // Интервал для рассылки beacon
  int _channel; // Канал для всех вирт. точек
  Vector<Subscription> _subscription_list;
  bool _debug;
  HashTable<EtherAddress, String> _packet_buffer;
  void match_against_subscriptions(StationStats stats, EtherAddress src);

private:
  void compute_bssid_mask ();
  void update_rx_stats(Packet *p);
  EtherAddress _hw_mac_addr;
  class AvailableRates *_rtable;
  int _associd;
  Timer _beacon_timer;
  Timer _cleanup_timer;
  IPAddress _default_gw_addr;
  String _debugfs_string;
};

CLICK_ENDDECLS
#endif
