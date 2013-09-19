//Название: Модуль виртуальной точки доступа
//Дата создания программы:02.06.2013
//Номер версии:1.0
//Дата последней модификации: 12.07.2013


/*
 * Copyright (C) 2013 Orenburg State University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");

 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0

 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,

 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

 */


#include <click/config.h>
#include <clicknet/wifi.h>
#include <click/router.hh>
#include <click/straccum.hh>
#include <click/args.hh>
#include <click/packet_anno.hh>
#include <click/handlercall.hh>
#include <clicknet/ether.h>
#include <clicknet/llc.h>
#include "vap.hh"

CLICK_DECLS

void cleanup_lvap (Timer *timer, void *);

Vap::Vap()
: _mean(0),
  _num_mean(0),
  _m2(0),
  _signal_offset(0),
  _debug(false),
  _rtable(0),
  _associd(0),
  _beacon_timer(this),
  _debugfs_string("")
{
  _cleanup_timer.assign (&cleanup_lvap, (void *) this);
}

Vap::~Vap()
{
}

int
Vap::initialize(ErrorHandler*)
{
  _beacon_timer.initialize(this);
  _cleanup_timer.initialize(this);
  _cleanup_timer.schedule_now();
  compute_bssid_mask ();
  return 0;
}

/*
 * таймер для рассылки beacon
 */
void
Vap::run_timer (Timer*)
{
  for (HashTable<EtherAddress, VapagentStationState>::iterator it 
      = _sta_mapping_table.begin(); it.live(); it++)
   {
      // beacon рассылаются по unicast адресам клиентов
      // ассоциированных с точкой
      // это предотвращает видимость не своих SSID клиентом

      for (int i = 0; i < it.value()._vap_ssids.size (); i++) {
        send_beacon (it.key(), it.value()._vap_bssid, it.value()._vap_ssids[i], false);
      }
   }
   
   _beacon_timer.reschedule_after_msec(_interval_ms);
}


/*
 * Наследуемый от Click метод для настройки
 */
int
Vap::configure(Vector<String> &conf, ErrorHandler *errh)
{ 
  _interval_ms = 5000;
  _channel = 6;
  if (Args(conf, this, errh)
  .read_mp("HWADDR", _hw_mac_addr)
  .read_m("RT", ElementCastArg("AvailableRates"), _rtable)
  .read_m("CHANNEL", _channel)
  .read_m("DEFAULT_GW", _default_gw_addr)
  .read_m("DEBUGFS", _debugfs_string)
  .complete() < 0)
  return -1;
  
  return 0;
}


/*
 * Пересчитываем маску BSSID для узла
 * используя все BSSID всех VAP
 * устанавливаем аппаратные переменные.
 */
void
Vap::compute_bssid_mask()
{
  uint8_t bssid_mask[6];
  int i;

  // Начальная маска ff:ff:ff:ff:ff:ff
  for (i = 0; i < 6; i++) 
    {
      bssid_mask[i] = 0xff;
    }

  // Для каждой VAP формируем маску с общими битами
  for (HashTable<EtherAddress, VapagentStationState>::iterator it 
      = _sta_mapping_table.begin(); it.live(); it++)
   {
     for (i = 0; i < 6; i++)
        {
          const uint8_t *hw= (const uint8_t *)_hw_mac_addr.data();
          const uint8_t *bssid= (const uint8_t *)it.value()._vap_bssid.data();
          bssid_mask[i] &= ~(hw[i] ^ bssid[i]);
        }
  
   }
  
  // Сообщаем драйверу о новой маске. Драйвер должен быть пропатчен заранее. 
  //Для обмена используем debugfs файл

  FILE *debugfs_file = fopen (_debugfs_string.c_str(),"w");
  
  if (debugfs_file!=NULL)
    {
      fprintf(stderr, "%s\n", EtherAddress (bssid_mask).unparse_colon().c_str());
      fprintf(debugfs_file, "%s\n", EtherAddress (bssid_mask).unparse_colon().c_str());//, sa.take_string().c_str());
      fclose (debugfs_file);
    }
}

/** 
 * Добавляем клиента к VAP
 * -1 если не получилось или уже он был добавлен
 */
int
Vap::add_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> vap_ssids)
{
  // Проверяем, есть ли VAP на этой ТД
  // иначе выход
  if (_sta_mapping_table.find(sta_mac) != _sta_mapping_table.end())
  {
    fprintf(stderr, "Ignoring VAP add request because it has already been assigned a slot\n");
    return -1;
  }

  VapagentStationState state;
  state._vap_bssid = sta_bssid;
  state._sta_ip_addr_v4 = sta_ip;
  state._vap_ssids = vap_ssids;
  _sta_mapping_table.set(sta_mac, state);

  // Эмулируем ARP ответ для IP ТД
  Router *r = router();
  HandlerCall::call_write (r->find("fh_arpr"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());

  compute_bssid_mask();

  // Посылаем beacon
  if (_sta_mapping_table.size() == 1) {
      _beacon_timer.schedule_now();
  }

  // Ассоциируем клиента в хеш таблице
  HashTable<EtherAddress, String>::const_iterator it = _packet_buffer.find(sta_mac);
  if (it != _packet_buffer.end()) {
    VapagentStationState oss = _sta_mapping_table.get (sta_mac);

    if (it.value() == "") {
      for (int i = 0; i < oss._vap_ssids.size(); i++) {
        send_beacon(sta_mac, oss._vap_bssid, oss._vap_ssids[i], true);    
      }
    }
    else {
      for (int i = 0; i < oss._vap_ssids.size(); i++) {
        if (oss._vap_ssids[i] == it.value()) {
          send_beacon(sta_mac, oss._vap_bssid, it.value(), true);
          break;
        }
      }
    }

    _packet_buffer.erase(it.key());
  }

  return 0;
}


/** 
 * Обновляем информацию о клиенте
* и его IP адресе
 *
 * return -1 если клиент уже существует и актуален
 */
int
Vap::set_vap (EtherAddress sta_mac, IPAddress sta_ip, EtherAddress sta_bssid, Vector<String> vap_ssids)
{
  if (_debug) {
    fprintf(stderr, "set_vap (%s, %s, %s, %s)\n", sta_mac.unparse_colon().c_str()
                                                , sta_ip.unparse().c_str()
                                                , sta_bssid.unparse().c_str()
                                                , vap_ssids[0].c_str());
  }

  // Уже есть клиент? Если да, то выход
  if (_sta_mapping_table.find(sta_mac) == _sta_mapping_table.end())
  {
    fprintf(stderr, "Ignoring LVAP set request because the agent isn't hosting the LVAP\n");
    return -1;
  }

  VapagentStationState state;
  state._vap_bssid = sta_bssid;
  state._sta_ip_addr_v4 = sta_ip;
  state._vap_ssids = vap_ssids;
  _sta_mapping_table.set(sta_mac, state);

  // Эмулируем ARP ответ о адресе ТД
  Router *r = router();
  HandlerCall::call_write (r->find("fh_arpr"), "add", state._sta_ip_addr_v4.unparse() + " " + sta_mac.unparse_colon());

  compute_bssid_mask();

  return 0;
}


/** 
 * Удаление клиента из ТД
 */
int
Vap::remove_vap (EtherAddress sta_mac)
{
  if (_debug) {
    fprintf(stderr, "remove_vap (%s)\n", sta_mac.unparse_colon().c_str());
  }

  HashTable<EtherAddress, VapagentStationState>::iterator it = _sta_mapping_table.find (sta_mac);
      
  // Если нет такой VAP на ТД то выход
  if (it == _sta_mapping_table.end())
    return -1;

  // Эмулируем ARP ответ на адрес ТД
  Router *r = router();
  HandlerCall::call_write (r->find("fh_arpr"), "remove", it.value()._sta_ip_addr_v4.unparse() + "/32");

  _sta_mapping_table.erase (it);
  
  // Удаляем BSSID из маски
  compute_bssid_mask();

  // Прекращаем генерацию beacon
  if (_sta_mapping_table.size() == 0) {
    _beacon_timer.unschedule();
  }

  return 0;
} 


/** 
 * Обрабатываем запрос на SSID от клиента (probe)
 * он наследован из ProbeResponder 
 * и берет  BSSID/SSID из хеш таблиц про VAP
 * sta_mapping_table
 */
void
Vap::recv_probe_request (Packet *p)
{

  struct click_wifi *w = (struct click_wifi *) p->data();
  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

  uint8_t *end  = (uint8_t *) p->data() + p->length();

  uint8_t *ssid_l = NULL;
  uint8_t *rates_l = NULL;

  while (ptr < end) {
  switch (*ptr) {
  case WIFI_ELEMID_SSID:
    ssid_l = ptr;
    break;
  case WIFI_ELEMID_RATES:
    rates_l = ptr;
    break;
  default:
    break;
  }
  ptr += ptr[1] + 2;

  }

  String ssid = "";
  if (ssid_l && ssid_l[1]) {
    ssid = String((char *) ssid_l + 2, WIFI_MIN((int)ssid_l[1], WIFI_NWID_MAXSIZE));
  }

  EtherAddress src = EtherAddress(w->i_addr2);
  
  // если VAP нет на эту ТД, запрашиваем контроллер
  if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
    StringAccum sa;
    sa << "probe " << src.unparse_colon().c_str() << " " << ssid << "\n";
    String payload = sa.take_string();
    WritablePacket *vapagent_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
    output(3).push(vapagent_probe_packet);
    _packet_buffer.set (src, ssid);
    p->kill();
    return;
  }

  VapagentStationState oss = _sta_mapping_table.get (src);

  /* Если клиент делает активный скан эфира,
   * посылаем ему все SSID,
   * иначе посылаем ему только ассоциированную SSID
   * */


  if (ssid != "") { 
    for (int i = 0; i < oss._vap_ssids.size(); i++) {
      if (oss._vap_ssids[i] == ssid) {
        send_beacon(src, oss._vap_bssid, ssid, true);
        break;
      }
    }
  }

  p->kill();
  return;
}


/** 
 * Посылка ответа на скан или beacon
 * Наследован из BeaconSource, но 
 * берет BSSID/SSID из sta_mapping_table
 */
void
Vap::send_beacon (EtherAddress dst, EtherAddress bssid, String my_ssid, bool probe) {
  Vector<int> rates = _rtable->lookup(bssid);

  /* Собираем пакет по 802.11b стандарту
   * он совместим с 802.11g */
  int max_len = sizeof (struct click_wifi) +
    8 +                  /* временная метка */
    2 +                  /* интервал для beacon */
    2 +                  /* информация о возможностях */
    2 + my_ssid.length() + /* ssid */
    2 + WIFI_RATES_MAXSIZE +  /* скорости */
    2 + 1 +              /* параметры ds */
    2 + 4 +              /* время */
    /* 802.11g поля */
    2 + WIFI_RATES_MAXSIZE +  /* дополнительные скорости */
    0;

  WritablePacket *p = Packet::make(max_len);
  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT;
  if (probe) {
    w->i_fc[0] |= WIFI_FC0_SUBTYPE_PROBE_RESP;
  } else {
    w->i_fc[0] |=  WIFI_FC0_SUBTYPE_BEACON;
  }

  w->i_fc[1] = WIFI_FC1_DIR_NODS;

  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, bssid.data(), 6);

  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
  int actual_length = sizeof (struct click_wifi);


  /* формируем временную метку */
  memset(ptr, 0, 8);
  ptr += 8;
  actual_length += 8;

  uint16_t beacon_int = (uint16_t) _interval_ms;
  *(uint16_t *)ptr = cpu_to_le16(beacon_int);
  ptr += 2;
  actual_length += 2;

  uint16_t cap_info = 0;
  cap_info |= WIFI_CAPINFO_ESS;
  *(uint16_t *)ptr = cpu_to_le16(cap_info);
  ptr += 2;
  actual_length += 2;

  /* ssid */
  ptr[0] = WIFI_ELEMID_SSID;
  ptr[1] = my_ssid.length();
  memcpy(ptr + 2, my_ssid.data(), my_ssid.length());
  ptr += 2 + my_ssid.length();
  actual_length += 2 + my_ssid.length();

  /* скорости */
  ptr[0] = WIFI_ELEMID_RATES;
  ptr[1] = WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  for (int x = 0; x < WIFI_MIN(WIFI_RATE_SIZE, rates.size()); x++) {
    ptr[2 + x] = (uint8_t) rates[x];

    if (rates[x] == 2) {
      ptr [2 + x] |= WIFI_RATE_BASIC;
    }

  }
  ptr += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  actual_length += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());


  /* канал */
  ptr[0] = WIFI_ELEMID_DSPARMS;
  ptr[1] = 1;
  ptr[2] = (uint8_t) _channel;
  ptr += 2 + 1;
  actual_length += 2 + 1;

  /* время */

  ptr[0] = WIFI_ELEMID_TIM;
  ptr[1] = 4;

  ptr[2] = 0; //кол-во
  ptr[3] = 1; //период
  ptr[4] = 0; //маска
  ptr[5] = 0; //частичная виртуальная маска
  ptr += 2 + 4;
  actual_length += 2 + 4;

  /* поля 802.11g */
  /* дополнительные скорости */
  int num_xrates = rates.size() - WIFI_RATE_SIZE;
  if (num_xrates > 0) {
    /* скорости */
    ptr[0] = WIFI_ELEMID_XRATES;
    ptr[1] = num_xrates;
    for (int x = 0; x < num_xrates; x++) {
      ptr[2 + x] = (uint8_t) rates[x + WIFI_RATE_SIZE];

      if (rates[x + WIFI_RATE_SIZE] == 2) {
        ptr [2 + x] |= WIFI_RATE_BASIC;
      }

    }
    ptr += 2 + num_xrates;
    actual_length += 2 + num_xrates;
  }

  p->take(max_len - actual_length);

  Timestamp now = Timestamp::now();
  Timestamp old =  _mean_table.get (dst);

  if (old != NULL) {

    Timestamp diff = now - old;
    double new_val = diff.sec() * 1000000000 + diff.usec();

    fprintf(stderr, "Out: %f\n", new_val);

    _num_mean++;
    double delta = new_val - _mean;
    _mean = _mean + delta/_num_mean;
    _m2 = _m2 + delta * (new_val - _mean);
    _mean_table.erase (dst);
  }

  output(0).push(p);
}

/** 
 * Прием  association запроса
 * Наследуется из  AssociationResponder, но
 * берет  BSSID/SSID из  sta_mapping_table
 */
void
Vap::recv_assoc_request (Packet *p) {
  struct click_wifi *w = (struct click_wifi *) p->data();

  EtherAddress dst = EtherAddress(w->i_addr1);
  EtherAddress src = EtherAddress(w->i_addr2);
  EtherAddress bssid = EtherAddress(w->i_addr3);

  // Если VAP нет на ТД, то выход
  if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
    p->kill();
    return;
  }

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

  /*поле возможностей */
  uint16_t capability = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;

  /* интервал прослушивания */
  uint16_t lint = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;

  uint8_t *end  = (uint8_t *) p->data() + p->length();

  uint8_t *ssid_l = NULL;
  uint8_t *rates_l = NULL;

  while (ptr < end) {
    switch (*ptr) {
      case WIFI_ELEMID_SSID:
          ssid_l = ptr;
          break;
      case WIFI_ELEMID_RATES:
          rates_l = ptr;
          break;
      default:
          {
            break;
          }
    }
    ptr += ptr[1] + 2;
  }

  Vector<int> basic_rates;
  Vector<int> rates;
  Vector<int> all_rates;
  if (rates_l) {
    for (int x = 0; x < WIFI_MIN((int)rates_l[1], WIFI_RATES_MAXSIZE); x++) {
        uint8_t rate = rates_l[x + 2];

        if (rate & WIFI_RATE_BASIC) {
      basic_rates.push_back((int)(rate & WIFI_RATE_VAL));
        } else {
      rates.push_back((int)(rate & WIFI_RATE_VAL));
        }
          all_rates.push_back((int)(rate & WIFI_RATE_VAL));
    }
  }

  VapagentStationState *oss = _sta_mapping_table.get_pointer (src);

  if (oss == NULL) {
    p->kill();
    return;
  }

  String ssid;
  String my_ssid = oss->_vap_ssids[0];
  if (ssid_l && ssid_l[1]) {
    ssid = String((char *) ssid_l + 2, WIFI_MIN((int)ssid_l[1], WIFI_NWID_MAXSIZE));
  } else {
    /* пустой или несуществующий */
    ssid = "";
  }

  uint16_t associd = 0xc000 | _associd++;

  send_assoc_response(src, WIFI_STATUS_SUCCESS, associd);
  p->kill();
  return;
}


/** 
 * Посылка запроса на association 
 * Наследован из AssociationResponder, но
 * берет  BSSID/SSID из sta_mapping_table
 */
void
Vap::send_assoc_response (EtherAddress dst, uint16_t status, uint16_t associd) {
  EtherAddress bssid = _sta_mapping_table.get (dst)._vap_bssid;

  Vector<int> rates = _rtable->lookup(bssid);
  int max_len = sizeof (struct click_wifi) +
    2 +                  /* поле возможностей */
    2 +                  /* статус */
    2 +                  /* assoc_id */
    2 + WIFI_RATES_MAXSIZE +  /* скорости */
    2 + WIFI_RATES_MAXSIZE +  /* доп. скорости */
    0;

  WritablePacket *p = Packet::make(max_len);

  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT | WIFI_FC0_SUBTYPE_ASSOC_RESP;
  w->i_fc[1] = WIFI_FC1_DIR_NODS;

  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, bssid.data(), 6);


  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);
  int actual_length = sizeof(struct click_wifi);

  uint16_t cap_info = 0;
  cap_info |= WIFI_CAPINFO_ESS;
  *(uint16_t *)ptr = cpu_to_le16(cap_info);
  ptr += 2;
  actual_length += 2;

  *(uint16_t *)ptr = cpu_to_le16(status);
  ptr += 2;
  actual_length += 2;

  *(uint16_t *)ptr = cpu_to_le16(associd);
  ptr += 2;
  actual_length += 2;


  /* скорости */
  ptr[0] = WIFI_ELEMID_RATES;
  ptr[1] = WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  for (int x = 0; x < WIFI_MIN(WIFI_RATE_SIZE, rates.size()); x++) {
    ptr[2 + x] = (uint8_t) rates[x];

    if (rates[x] == 2) {
      ptr [2 + x] |= WIFI_RATE_BASIC;
    }

  }
  ptr += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());
  actual_length += 2 + WIFI_MIN(WIFI_RATE_SIZE, rates.size());


  int num_xrates = rates.size() - WIFI_RATE_SIZE;
  if (num_xrates > 0) {
    /* скорости */
    ptr[0] = WIFI_ELEMID_XRATES;
    ptr[1] = num_xrates;
    for (int x = 0; x < num_xrates; x++) {
      ptr[2 + x] = (uint8_t) rates[x + WIFI_RATE_SIZE];

      if (rates[x + WIFI_RATE_SIZE] == 2) {
  ptr [2 + x] |= WIFI_RATE_BASIC;
      }

    }
    ptr += 2 + num_xrates;
    actual_length += 2 + num_xrates;
  }

  p->take(max_len - actual_length);

  output(0).push(p);
}


/** 
 * Прием Open Auth запроса
 * наследован из OpenAuthResponder , но
 * берет  BSSID/SSID из sta_mapping_table
 */
void
Vap::recv_open_auth_request (Packet *p) {
  struct click_wifi *w = (struct click_wifi *) p->data();

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);



  uint16_t algo = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;

  uint16_t seq = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;

  uint16_t status = le16_to_cpu(*(uint16_t *) ptr);
  ptr += 2;


  EtherAddress src = EtherAddress(w->i_addr2);

  //Если VAP не на этой ТД, выход
  if (_sta_mapping_table.find(src) == _sta_mapping_table.end()) {
    p->kill();
    return;
  }

  if (algo != WIFI_AUTH_ALG_OPEN) {
    p->kill();
    return;
  }

  if (seq != 1) {
    p->kill();
    return;
  }

  send_open_auth_response(src, 2, WIFI_STATUS_SUCCESS);

  p->kill();
  return;
}


/** 
 * Посылка запроса Open Auth. 
 * наследован из  OpenAuthResponder, но
 * берет BSSID/SSID из sta_mapping_table
 */
void
Vap::send_open_auth_response (EtherAddress dst, uint16_t seq, uint16_t status) {
  
  VapagentStationState oss = _sta_mapping_table.get (dst);

  int len = sizeof (struct click_wifi) +
    2 +                  /* alg */
    2 +                  /* seq */
    2 +                  /* статус */
    0;

  WritablePacket *p = Packet::make(len);

  if (p == 0)
    return;

  struct click_wifi *w = (struct click_wifi *) p->data();

  w->i_fc[0] = WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_MGT | WIFI_FC0_SUBTYPE_AUTH;
  w->i_fc[1] = WIFI_FC1_DIR_NODS;

  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, oss._vap_bssid.data(), 6);
  memcpy(w->i_addr3, oss._vap_bssid.data(), 6);


  w->i_dur = 0;
  w->i_seq = 0;

  uint8_t *ptr;

  ptr = (uint8_t *) p->data() + sizeof(struct click_wifi);

  *(uint16_t *)ptr = cpu_to_le16(WIFI_AUTH_ALG_OPEN);
  ptr += 2;

  *(uint16_t *)ptr = cpu_to_le16(seq);
  ptr += 2;

  *(uint16_t *)ptr = cpu_to_le16(status);
  ptr += 2;

  output(0).push(p);
}


/** 
 * Инкапсулируем Ethernet в 802.11 заголовок
 * наследован из WifiEncap, но
 * использует режим FromDS (0x02)
 */
Packet*
Vap::wifi_encap (Packet *p, EtherAddress bssid)
{
  EtherAddress src;
  EtherAddress dst;

  uint16_t ethtype;
  WritablePacket *p_out = 0;

  if (p->length() < sizeof(struct click_ether)) {
    
    p->kill();
    return 0;

  }

  click_ether *eh = (click_ether *) p->data();
  src = EtherAddress(eh->ether_shost);
  dst = EtherAddress(eh->ether_dhost);
  memcpy(&ethtype, p->data() + 12, 2);

  p_out = p->uniqueify();
  if (!p_out) {
    return 0;
  }


  p_out->pull(sizeof(struct click_ether));
  p_out = p_out->push(sizeof(struct click_llc));

  if (!p_out) {
    return 0;
  }

  memcpy(p_out->data(), WIFI_LLC_HEADER, WIFI_LLC_HEADER_LEN);
  memcpy(p_out->data() + 6, &ethtype, 2);

  if (!(p_out = p_out->push(sizeof(struct click_wifi))))
      return 0;
  struct click_wifi *w = (struct click_wifi *) p_out->data();

  memset(p_out->data(), 0, sizeof(click_wifi));
  w->i_fc[0] = (uint8_t) (WIFI_FC0_VERSION_0 | WIFI_FC0_TYPE_DATA);
  w->i_fc[1] = 0;
  w->i_fc[1] |= (uint8_t) (WIFI_FC1_DIR_MASK & WIFI_FC1_DIR_FROMDS);

  // Переключаем режим в  0x02
  memcpy(w->i_addr1, dst.data(), 6);
  memcpy(w->i_addr2, bssid.data(), 6);
  memcpy(w->i_addr3, src.data(), 6);

  return p_out;
}

void
Vap::update_rx_stats(Packet *p)
{
  struct click_wifi *w = (struct click_wifi *) p->data();
  EtherAddress src = EtherAddress(w->i_addr2);

  struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);

  StationStats stat;
  HashTable<EtherAddress, StationStats>::const_iterator it = _rx_stats.find(src);
  if (it == _rx_stats.end())
    stat = StationStats();
  else
    stat = it.value();

  stat._rate = ceh->rate;
  stat._noise = ceh->silence;
  stat._signal = ceh->rssi + _signal_offset;
  stat._packets++;
  stat._last_received.assign_now();

  match_against_subscriptions(stat, src);

  _rx_stats.set (src, stat);
}

/** 
 * Собственно модуль. Имеет 2 входящих и 4 исходящих 
 * виртуальных порта с точки зрения Click маршрутизатора
 *
 * In-port-0: Фрейм 802.11. Приходит с физического устройства
 * In-port-1: Ethernet фрейм из тунеля TAP
 *
 * Out-port-0: Если на порт  in-port-0 пришел управляющий фрейм 802.11,
 *             отсюда посылается ответ.
 * Out-port-1: Если на порт  in-port-0 пришел фрейм данных 802.11,
 *             отсюда данные уходят дальше по стеку TCP/IP.
 * Out-port-2: если на in-port-1 пришел фрейм для уже ассоциированного клиента,
 *              для которого уже есть VAP перенаправляем ему пакет.
 * Out-port-3:Используется для связи с контроллером
. */
void
Vap::push(int port, Packet *p)
{
  // если port == 0, значит это пакет  802.11
  // Фильтруем тольк пакеты данных для VAPs,
  // и обрабатываем управляющие пакеты соотв. методом.
  
  if (port == 0) {
    // if port == 0, пакет пришел из физического интерфейса

    if (p->length() < sizeof(struct click_wifi)) {
      p->kill();
      return;
    }

    uint8_t type;
    uint8_t subtype;

    struct click_wifi *w = (struct click_wifi *) p->data();

    EtherAddress src = EtherAddress(w->i_addr2);
    update_rx_stats(p);

    type = w->i_fc[0] & WIFI_FC0_TYPE_MASK;
    subtype = w->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;
  
    if (type == WIFI_FC0_TYPE_MGT) {

      // это управляющий пакет
      // смотрим его subtype
      switch (subtype) {
        case WIFI_FC0_SUBTYPE_PROBE_REQ:
          {
            recv_probe_request (p);
            return;
          }
        case WIFI_FC0_SUBTYPE_ASSOC_REQ:
          {
            recv_assoc_request (p);
            return;
          }
        case WIFI_FC0_SUBTYPE_AUTH:
          {
            recv_open_auth_request (p);
            return;
          }
        default:
          {
            // Остальные управляющие пакеты не обрабатываем совсем
            p->kill ();
            return;
          }
      }
    }
    else if (type == WIFI_FC0_TYPE_DATA) {

      // Это фрейм с данными
      // отправляем дальше в VAPs.
      if (_sta_mapping_table.find (src) == _sta_mapping_table.end()) {
        // если клиента нет, выход
        p->kill ();
        return;
      }

      // отправляем в  WifiDecap для декапсуляции.
      output(1).push(p);
      return;
    }
  }
  else if (port == 1) {
    // Пакет пришел снаружи с высоких уровней (IP)
    // пробуем послать его с соотв.
    // bssid и wifi-инкапсуляцией.
    const click_ether *e = (const click_ether *) (p->data() + 0 /*offset*/);
    const unsigned char *daddr = (const unsigned char *)e->ether_dhost;

    EtherAddress eth (daddr);

    if (_sta_mapping_table.find (eth) != _sta_mapping_table.end ())
    {
      VapagentStationState oss = _sta_mapping_table.get (eth);
        
      // Если это ARP ответ, исправляем MAC на BSSID VAP
      if (ntohs(e->ether_type) == ETHERTYPE_ARP) {
        click_ether_arp *ea = (click_ether_arp *) (e + 1);
        if (ntohs(ea->ea_hdr.ar_hrd) == ARPHRD_ETHER
            && ntohs(ea->ea_hdr.ar_pro) == ETHERTYPE_IP
            && ntohs(ea->ea_hdr.ar_op) == ARPOP_REPLY) {
          
          IPAddress ipa = IPAddress(ea->arp_spa);
          if (ipa == _default_gw_addr)
            memcpy(ea->arp_sha, oss._vap_bssid.data(), 6);
        }
      }
      Packet *p_out = wifi_encap (p, oss._vap_bssid);
      output(2).push(p_out);
      return;
    }
  }

  p->kill();
  return;
}

void
Vap::add_subscription (long subscription_id, EtherAddress addr, String statistic, relation_t r, double val)
{
  Subscription sub;
  sub.subscription_id = subscription_id;
  sub.sta_addr = addr;
  sub.statistic = statistic;
  sub.rel = r;
  sub.val = val;
  _subscription_list.push_back (sub);
}

void
Vap::clear_subscriptions ()
{
  _subscription_list.clear();
}

void
Vap::match_against_subscriptions(StationStats stats, EtherAddress src)
{
  if(_subscription_list.size() == 0)
    return;

  int count = 0;
  StringAccum subscription_matches;

  for (Vector<Vap::Subscription>::const_iterator iter = _subscription_list.begin();
           iter != _subscription_list.end(); iter++) {
    
    Subscription sub = *iter;

    if (sub.sta_addr != EtherAddress() && sub.sta_addr != src)
      continue;

    switch (sub.rel) {
      case EQUALS: {
        if (sub.statistic == "signal" && stats._signal == sub.val) {
          subscription_matches << " " << sub.subscription_id << ":" << stats._signal;
          count++;
        } else if (sub.statistic == "rate" && stats._rate == sub.val) {
          subscription_matches << " " <<  sub.subscription_id << ":" << stats._rate;
          count++;
        } else if (sub.statistic == "noise" && stats._noise == sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._noise;
          count++;
        } else if (sub.statistic == "_packets" && stats._packets == sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._packets;
          count++;
        }
        break;
      }
      case GREATER_THAN: {
       if (sub.statistic == "signal" && stats._signal > sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._signal;
          count++;
        } else if (sub.statistic == "rate" && stats._rate > sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._rate;
          count++;
        } else if (sub.statistic == "noise" && stats._noise > sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._noise;
          count++;
        } else if (sub.statistic == "_packets" && stats._packets > sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._packets;
          count++;
        }
        break; 
      }
      case LESSER_THAN: {
        if (sub.statistic == "signal" && stats._signal < sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._signal;
          count++;
        } else if (sub.statistic == "rate" && stats._rate < sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._rate;
          count++;
        } else if (sub.statistic == "noise" && stats._noise < sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._noise;
          count++;
        } else if (sub.statistic == "_packets" && stats._packets < sub.val) {
          subscription_matches <<  " " << sub.subscription_id << ":" << stats._packets;
          count++;
        }
        break;
      }
    }
  }


  StringAccum sa;
  sa << "publish " << src.unparse_colon().c_str() << " " << count << subscription_matches.take_string() << "\n";

  String payload = sa.take_string();
  WritablePacket *vapagent_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
  output(3).push(vapagent_probe_packet);
}

String
Vap::read_handler(Element *e, void *user_data)
{
  Vap *agent = (Vap *) e;
  StringAccum sa;

  switch (reinterpret_cast<uintptr_t>(user_data)) {
    case handler_view_mapping_table: {
      for (HashTable<EtherAddress, VapagentStationState>::iterator it 
          = agent->_sta_mapping_table.begin(); it.live(); it++)
        {
          sa << it.key().unparse_colon() 
            << " " << it.value()._sta_ip_addr_v4
            <<  " " << it.value()._vap_bssid.unparse_colon(); 

          for (int i = 0; i < it.value()._vap_ssids.size(); i++) {
            sa << " " << it.value()._vap_ssids[i];
          }

          sa << "\n";
        }
      break;
    }
    case handler_channel: {
      sa << agent->_channel << "\n";
      break;
    }
    case handler_interval: {
      sa << agent->_interval_ms << "\n";
      break;
    }
    case handler_rxstat: {
      Timestamp now = Timestamp::now();

      for (HashTable<EtherAddress, StationStats>::const_iterator iter = agent->_rx_stats.begin();
           iter.live(); iter++) {
   // формируем статистику в человекочитабельном виде
        Vap::StationStats n = iter.value();
        Timestamp age = now - n._last_received;
        sa << iter.key().unparse_colon();
        sa << " rate:" << n._rate;
        sa << " signal:" << n._signal;
        sa << " noise:" << n._noise;
        // sa << " avg_signal " << avg_signal;
        // sa << " avg_noise " << avg_noise;
        // sa << " total_signal " << n._sum_signal;
        // sa << " total_noise " << n._sum_noise;
        sa << " packets:" << n._packets;
        sa << " last_received:" << age << "\n";
      }

      break;
    }
    case handler_subscriptions: {

      for (Vector<Vap::Subscription>::const_iterator iter = agent->_subscription_list.begin();
           iter != agent->_subscription_list.end(); iter++) {
        
        Vap::Subscription sub = *iter;
        sa << "sub_id " << sub.subscription_id;
        sa << " addr " << sub.sta_addr.unparse_colon();
        sa << " stat " << sub.statistic;
        sa << " rel " << sub.rel;
        sa << " val " << sub.val;
        sa << "\n";
      }

      break;
    }
    case handler_debug: {
      sa << agent->_debug << "\n";
      break;
    }
    case handler_report_mean: {
      double variance = agent->_m2 / (agent->_num_mean -1);
      sa << agent->_mean <<  " " <<  agent->_num_mean << " " << variance << "\n";
      break;
    }
  }

  return sa.take_string();
}

int
Vap::write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh)
{

  Vap *agent = (Vap *) e;

  switch (reinterpret_cast<uintptr_t>(user_data)) {
    case handler_add_vap:{
      IPAddress sta_ip;
      EtherAddress sta_mac;
      EtherAddress vap_bssid;
      
      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("STA_IP", sta_ip)
            .read_mp("VAP_BSSID", vap_bssid)
            .consume() < 0)
        {
          return -1;
        }

      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }
      
      if (agent->add_vap (sta_mac, sta_ip, vap_bssid, ssidList) < 0)
        {
          return -1;
        }
      break;
    }
    case handler_set_vap:{
      IPAddress sta_ip;
      EtherAddress sta_mac;
      EtherAddress vap_bssid;
      
      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("STA_IP", sta_ip)
            .read_mp("VAP_BSSID", vap_bssid)
            .consume() < 0)
        {
          return -1;
        }

      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }
      
      if (agent->set_vap (sta_mac, sta_ip, vap_bssid, ssidList) < 0)
        {
          return -1;
        }
      break;
    }
    case handler_remove_vap:{
      EtherAddress sta_mac;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("STA_MAC", sta_mac)
        .complete() < 0)
        {
          return -1;
        }

      if (agent->remove_vap(sta_mac) < 0)
        {
          return -1;
        }
      break;
    }
    case handler_channel: {
      int channel;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("CHANNEL", channel)
        .complete() < 0)
        {
          return -1;
        }

      agent->_channel = channel;
      break;
    }
    case handler_interval: {
      int interval;
      if (Args(agent, errh).push_back_words(str)
        .read_mp("INTERVAL", interval)
        .complete() < 0)
        {
          return -1;
        }

      agent->_interval_ms = interval;     
      break;
    }
    case handler_subscriptions: {
      /* очищаем все подписки на события */
      agent->clear_subscriptions();

      int num_rows;
      Args args(agent, errh);
      if (args.push_back_words(str)
        .read_mp("NUM_ROWS", num_rows)
        .consume() < 0)
        {
          return -1;
        }
      
      fprintf(stderr, "num_rows: %d\n", num_rows);
      for (int i = 0; i < num_rows; i++) {
        long sub_id;
        EtherAddress sta_addr;
        String statistic;
        int relation;
        double value;
        if (args
            .read_mp("sub_id", sub_id)
            .read_mp("addr", sta_addr)
            .read_mp("stat", statistic)
            .read_mp("rel", relation)
            .read_mp("val", value)
            .consume() < 0)
          {
            return -1;
          }

        agent->add_subscription (sub_id, sta_addr, statistic, static_cast<relation_t>(relation), value);
      }

      if (args.complete() < 0) {
        return -1;
      }
      break;
    }
    case handler_debug: {
      bool debug;
      if (!BoolArg().parse(str, debug))
        return -1;
      
      agent->_debug = debug;
      break;
    }
    case handler_probe_response: {

      EtherAddress sta_mac;
      EtherAddress vap_bssid;
      
      Args args = Args(agent, errh).push_back_words(str);
      if (args.read_mp("STA_MAC", sta_mac)
            .read_mp("VAP_BSSID", vap_bssid)
            .consume() < 0)
        {
          return -1;
        }

      Vector<String> ssidList;
      while (!args.empty()) {
        String vap_ssid;
        if (args.read_mp("VAP_SSID", vap_ssid)
              .consume() < 0)
          {
            return -1;
          }
        ssidList.push_back(vap_ssid);
      }

      for (Vector<String>::const_iterator it = ssidList.begin();
            it != ssidList.end(); it++) {
        agent->send_beacon (sta_mac, vap_bssid, *it, true);
      }
      break;
    }
    case handler_probe_request: {
      EtherAddress sta_mac;
      String ssid = "";

      Args args = Args(agent, errh).push_back_words(str);

      if (args.read_mp("STA_MAC", sta_mac)
          .consume() < 0)
        {
          return -1;
        }

      if (!args.empty()) {
        if (args.read_mp("SSID", ssid)
              .consume() < 0)
          {
            return -1;
          }
      }
      StringAccum sa;
      sa << "probe " << sta_mac.unparse_colon().c_str() << " " << ssid << "\n";
      String payload = sa.take_string();

      agent->_mean_table.set (sta_mac, Timestamp::now());
      WritablePacket *vapagent_probe_packet = Packet::make(Packet::default_headroom, payload.data(), payload.length(), 0);
      agent->output(3).push(vapagent_probe_packet);
      break;
    }
    case handler_update_signal_strength: {
      EtherAddress sta_mac;
      int value;
      
      Args args = Args(agent, errh).push_back_words(str);

      if (args.read_mp("STA_MAC", sta_mac)
          .read_mp("VALUE", value)
          .consume() < 0)
        {
          return -1;
        }      

      StationStats stat;
      HashTable<EtherAddress, StationStats>::const_iterator it = agent->_rx_stats.find(sta_mac);

      if (it == agent->_rx_stats.end())
        stat = StationStats();
      else
        stat = it.value();

      stat._signal = value;
      stat._packets++;
      stat._last_received.assign_now();

      agent->match_against_subscriptions(stat, sta_mac);
      agent->_rx_stats.set (sta_mac, stat);

      break;
    }
    case handler_signal_strength_offset: {
      int value;
      Args args = Args(agent, errh).push_back_words(str);

      if (args.read_mp("VALUE", value)
          .consume() < 0)
        {
          return -1;
        }

      agent->_signal_offset = value;
      break;
    }
  }
  return 0;
}

void
Vap::add_handlers()
{
  add_read_handler("table", read_handler, handler_view_mapping_table);
  add_read_handler("channel", read_handler, handler_channel);
  add_read_handler("interval", read_handler, handler_interval);
  add_read_handler("rxstats", read_handler, handler_rxstat);
  add_read_handler("subscriptions", read_handler, handler_subscriptions);
  add_read_handler("debug", read_handler, handler_debug);
  add_read_handler("report_mean", read_handler, handler_report_mean);

  add_write_handler("add_vap", write_handler, handler_add_vap);
  add_write_handler("set_vap", write_handler, handler_set_vap);
  add_write_handler("remove_vap", write_handler, handler_remove_vap);
  add_write_handler("channel", write_handler, handler_channel);
  add_write_handler("interval", write_handler, handler_interval);
  add_write_handler("subscriptions", write_handler, handler_subscriptions);
  add_write_handler("debug", write_handler, handler_debug);
  add_write_handler("send_probe_response", write_handler, handler_probe_response);
  add_write_handler("testing_send_probe_request", write_handler, handler_probe_request);
  add_write_handler("handler_update_signal_strength", write_handler, handler_update_signal_strength);
  add_write_handler("signal_strength_offset", write_handler, handler_signal_strength_offset);
}

void
cleanup_lvap (Timer *timer, void *data)
{
  Vap *agent = (Vap *) data;

  Vector<EtherAddress> buf;

  // Очищаем все старые записи.
  for (HashTable<EtherAddress, Vap::StationStats>::const_iterator iter = agent->_rx_stats.begin();
        iter.live(); iter++)
  {
    Timestamp now = Timestamp::now();
    Timestamp age = now - iter.value()._last_received;
    
    if (age.sec() > 30)
    {
      buf.push_back (iter.key());
    }
  }
  for (Vector<EtherAddress>::const_iterator iter = buf.begin(); iter != buf.end(); iter++)
  {
    agent->_rx_stats.erase (*iter);
  }
  agent->_packet_buffer.clear();
  timer->reschedule_after_sec(50);
}
CLICK_ENDDECLS
EXPORT_ELEMENT(Vap)
ELEMENT_REQUIRES(userlevel)
