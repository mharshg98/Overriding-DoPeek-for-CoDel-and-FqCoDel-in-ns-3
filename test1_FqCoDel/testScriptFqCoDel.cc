#include <iostream>
#include <fstream>
#include <string>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/error-model.h"
#include "ns3/tcp-header.h"
#include "ns3/udp-header.h"
#include "ns3/enum.h"
#include "ns3/event-id.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/traffic-control-module.h"
#include "ns3/queue-size.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("A NAME");

// The following code borrowed from Linux codel.h, for unit testing
#define REC_INV_SQRT_BITS_ns3 (8 * sizeof(uint16_t))
/* or sizeof_in_bits(rec_inv_sqrt) */
/* needed shift to get a Q0.32 number from rec_inv_sqrt */
#define REC_INV_SQRT_SHIFT_ns3 (32 - REC_INV_SQRT_BITS_ns3)

static uint16_t _codel_Newton_step (uint16_t rec_inv_sqrt, uint32_t count)
{
  uint32_t invsqrt = ((uint32_t)rec_inv_sqrt) << REC_INV_SQRT_SHIFT_ns3;
  uint32_t invsqrt2 = ((uint64_t)invsqrt * invsqrt) >> 32;
  uint64_t val = (3LL << 32) - ((uint64_t)count * invsqrt2);

  val >>= 2; /* avoid overflow in following multiply */
  val = (val * invsqrt) >> (32 - 2 + 1);
  return static_cast<uint16_t>(val >> REC_INV_SQRT_SHIFT_ns3);
}

static uint32_t _reciprocal_scale (uint32_t val, uint32_t ep_ro)
{
  return (uint32_t)(((uint64_t)val * ep_ro) >> 32);
}
// End Linux borrow

/**
 * \ingroup traffic-control-test
 * \ingroup tests
 *
 * \brief FqCodel Queue Disc Test Item
 */
class FqCodelQueueDiscTestItem : public QueueDiscItem {
public:
  /**
   * Constructor
   *
   * \param p packet
   * \param addr address
   * \param ecnCapable ECN capable
   */
  FqCodelQueueDiscTestItem (Ptr<Packet> p, const Address & addr, uint16_t protocol, bool ecnCapable);
  virtual ~FqCodelQueueDiscTestItem ();

  // Delete copy constructor and assignment operator to avoid misuse
  FqCodelQueueDiscTestItem (const FqCodelQueueDiscTestItem &) = delete;
  FqCodelQueueDiscTestItem & operator = (const FqCodelQueueDiscTestItem &) = delete;

  virtual void AddHeader (void);
  virtual bool Mark(void);

private:
  bool m_ecnCapablePacket; ///< ECN capable packet?
};

FqCodelQueueDiscTestItem::FqCodelQueueDiscTestItem (Ptr<Packet> p, const Address & addr, uint16_t protocol, bool ecnCapable)
  : QueueDiscItem (p, addr, protocol),
    m_ecnCapablePacket (ecnCapable)
{
}

FqCodelQueueDiscTestItem::~FqCodelQueueDiscTestItem ()
{
}

void
FqCodelQueueDiscTestItem::AddHeader (void)
{
}

bool
FqCodelQueueDiscTestItem::Mark (void)
{
  if (m_ecnCapablePacket)
    {
      return true;
    }
  return false;
}


/*
  Test Peek functionality in FqCoDel without ECN  
*/
class FqCoDelPeekTest : public TestCase
{
  public:
    FqCoDelPeekTest(QueueSizeUnit mode);
    void DoRun(void);
  private:
    void Enqueue(Ptr<FqCoDelQueueDisc> queue, uint32_t pktSize, uint32_t nPkt, uint16_t protocol);
    void Dequeue(Ptr<FqCoDelQueueDisc> queue);
    void Peek(Ptr<FqCoDelQueueDisc> queue);
    QueueSizeUnit m_mode;
    uint32_t m_peeked;
    std::string interval;
    std::string target;
};

FqCoDelPeekTest::FqCoDelPeekTest(QueueSizeUnit mode):
  TestCase("Basic Codel Peek test")
  {
    m_mode = mode;
    interval="100ms";
    target="5ms";
}

void 
FqCoDelPeekTest::DoRun()
{
  Ptr<FqCoDelQueueDisc> queue = CreateObject<FqCoDelQueueDisc> ();
  uint32_t pktSize = 1000;
  uint32_t modeSize = 0;
  if (m_mode == QueueSizeUnit::BYTES)
    {
        modeSize = pktSize;
    }
  else if (m_mode == QueueSizeUnit::PACKETS)
    {
        modeSize = 1;
    }

  Time Interval = Time(FqCoDelPeekTest::interval);
  Time Target = Time(FqCoDelPeekTest::target); 
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MaxSize", QueueSizeValue (QueueSize (m_mode, modeSize * 10240))),
                         true, "Verify that we can actually set the attribute MaxSize");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Interval", StringValue (FqCoDelPeekTest::interval)), true,
                         "Verify that we can actually set the attribute Interval");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Target", StringValue (FqCoDelPeekTest::target)), true,
                         "Verify that we can actually set the attribute Target");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("PeekFunction", BooleanValue (true)),
                         true, "Verify that we can actually set the attribute PeekFunction");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("UseEcn", BooleanValue (false)),
                         true, "Verify that we can actually set the attribute PeekFunction");
  queue->Initialize ();

  Enqueue(queue, pktSize, 5, 0);
  NS_LOG_UNCOND("Enqueue packets of Protocol(0) Done");
  Enqueue(queue, pktSize, 5, 1);
  NS_LOG_UNCOND("Enqueue packets of Protocol(1) Done");

  Time firstDequeueTime = 2 * Target;
  Simulator::Schedule(firstDequeueTime, &FqCoDelPeekTest::Dequeue, this, queue);

  Simulator::Schedule(firstDequeueTime, &FqCoDelPeekTest::Peek, this, queue);

  Time nextDequeueTime = firstDequeueTime + 2 * Interval;
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Peek, this, queue);
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Dequeue, this, queue);

  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Dequeue, this, queue);
  
  // Extra Dequeues
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Dequeue, this, queue);
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Peek, this, queue);

  nextDequeueTime = nextDequeueTime + 2 * Interval;
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Peek, this, queue);
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Dequeue, this, queue);

  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Dequeue, this, queue);

  // Decaying the flows
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Dequeue, this, queue);

  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Dequeue, this, queue);

  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Dequeue, this, queue);

  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTest::Dequeue, this, queue);

  Simulator::Run();
  Simulator::Destroy();
}

void 
FqCoDelPeekTest::Enqueue(Ptr<FqCoDelQueueDisc> queue, uint32_t pktSize, uint32_t nPkt, uint16_t protocol)
{
  Address addr;
  for (uint32_t i = 0; i < nPkt; i++)
    {
        Ptr<Packet> p = Create<Packet>(pktSize);
        queue->Enqueue(Create<FqCodelQueueDiscTestItem>(p, addr, protocol, false));
    }
}

void
FqCoDelPeekTest::Dequeue(Ptr<FqCoDelQueueDisc> queue) 
{
  uint64_t time = Simulator::Now().GetMilliSeconds();
  uint32_t beforeSize = queue->GetCurrentSize().GetValue();
  uint32_t beforeDroppedDequeue = queue->GetStats().GetNDroppedPackets(CoDelQueueDisc::TARGET_EXCEEDED_DROP);
  Ptr<QueueDiscItem> item = queue->Dequeue();
  m_peeked = false;
  if(item==0)
    NS_LOG_UNCOND("Queue Empty");
  uint32_t afterSize = queue->GetCurrentSize().GetValue();
  uint32_t afterDroppedDequeue = queue->GetStats().GetNDroppedPackets(CoDelQueueDisc::TARGET_EXCEEDED_DROP);
  NS_LOG_UNCOND("At " << time << "ms Dequeue");
  if(item)
    {
      NS_LOG_UNCOND("Packet id Dequeued " << item->GetPacket()->GetUid());
      NS_LOG_UNCOND("Queue Size before - " << beforeSize << " | Packets Dropped Before - " << beforeDroppedDequeue);
      NS_LOG_UNCOND("Queue Size after  - " << afterSize << " | Packets Dropped After  - " << afterDroppedDequeue << std::endl);
    }
}

void
FqCoDelPeekTest::Peek(Ptr<FqCoDelQueueDisc> queue){
  uint64_t time = Simulator::Now().GetMilliSeconds();
  uint32_t beforeSize = queue->GetCurrentSize().GetValue();
  uint32_t beforeDroppedDequeue = queue->GetStats().GetNDroppedPackets(CoDelQueueDisc::TARGET_EXCEEDED_DROP);
  Ptr<const QueueDiscItem> item = queue->Peek();
  m_peeked = true;
  if(item==0)
    NS_LOG_UNCOND("Queue Empty");
  uint32_t afterSize = queue->GetCurrentSize().GetValue();
  uint32_t afterDroppedDequeue = queue->GetStats().GetNDroppedPackets(CoDelQueueDisc::TARGET_EXCEEDED_DROP);
  NS_LOG_UNCOND("At " << time << "ms Peek");
  if(item)
    {
      NS_LOG_UNCOND("Packet id Peeked " << item->GetPacket()->GetUid());
      NS_LOG_UNCOND("Queue Size before - " << beforeSize << " | Packets Dropped Before - " << beforeDroppedDequeue);
      NS_LOG_UNCOND("Queue Size after  - " << afterSize << " | Packets Dropped After  - " << afterDroppedDequeue << std::endl);
    }
}


/*
  Test Peek functionality in FqCoDel with ECN  
*/
class FqCoDelPeekTestMark : public TestCase
{
  public:
    FqCoDelPeekTestMark(QueueSizeUnit mode);
    void DoRun(void);
  private:
    void Enqueue(Ptr<FqCoDelQueueDisc> queue, uint32_t pktSize, uint32_t nPkt, uint16_t protocol);
    void Dequeue(Ptr<FqCoDelQueueDisc> queue);
    void Peek(Ptr<FqCoDelQueueDisc> queue);
    QueueSizeUnit m_mode;
    uint32_t m_peeked;
    std::string interval;
    std::string target;
};

FqCoDelPeekTestMark::FqCoDelPeekTestMark(QueueSizeUnit mode):
  TestCase("Basic Codel Peek test")
  {
    m_mode = mode;
    interval="100ms";
    target="5ms";
}

void 
FqCoDelPeekTestMark::DoRun()
{
  Ptr<FqCoDelQueueDisc> queue = CreateObject<FqCoDelQueueDisc> ();
  uint32_t pktSize = 1000;
  uint32_t modeSize = 0;
  if (m_mode == QueueSizeUnit::BYTES)
    {
        modeSize = pktSize;
    }
  else if (m_mode == QueueSizeUnit::PACKETS)
    {
        modeSize = 1;
    }

  Time Interval = Time(FqCoDelPeekTestMark::interval);
  Time Target = Time(FqCoDelPeekTestMark::target); 
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MaxSize", QueueSizeValue (QueueSize (m_mode, modeSize * 10240))),
                         true, "Verify that we can actually set the attribute MaxSize");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Interval", StringValue (FqCoDelPeekTestMark::interval)), true,
                         "Verify that we can actually set the attribute Interval");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Target", StringValue (FqCoDelPeekTestMark::target)), true,
                         "Verify that we can actually set the attribute Target");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("PeekFunction", BooleanValue (true)),
                         true, "Verify that we can actually set the attribute PeekFunction");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("UseEcn", BooleanValue (true)),
                         true, "Verify that we can actually set the attribute PeekFunction");
  queue->Initialize ();

  Enqueue(queue, pktSize, 5, 0);
  NS_LOG_UNCOND("Enqueue packets of Protocol(0) Done");
  Enqueue(queue, pktSize, 5, 1);
  NS_LOG_UNCOND("Enqueue packets of Protocol(1) Done");

  Time firstDequeueTime = 2 * Target;
  Simulator::Schedule(firstDequeueTime, &FqCoDelPeekTestMark::Dequeue, this, queue);

  Simulator::Schedule(firstDequeueTime, &FqCoDelPeekTestMark::Peek, this, queue);

  Time nextDequeueTime = firstDequeueTime + 2 * Interval;
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Peek, this, queue);
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Dequeue, this, queue);

  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Dequeue, this, queue);
  
  // Extra Dequeues
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Dequeue, this, queue);
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Peek, this, queue);

  nextDequeueTime = nextDequeueTime + 2 * Interval;
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Peek, this, queue);
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Dequeue, this, queue);

  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Dequeue, this, queue);

  // Decaying the flows
  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Dequeue, this, queue);

  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Dequeue, this, queue);

  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Dequeue, this, queue);

  Simulator::Schedule(nextDequeueTime, &FqCoDelPeekTestMark::Dequeue, this, queue);

  Simulator::Run();
  Simulator::Destroy();
}

void 
FqCoDelPeekTestMark::Enqueue(Ptr<FqCoDelQueueDisc> queue, uint32_t pktSize, uint32_t nPkt, uint16_t protocol)
{
  Address addr;
  for (uint32_t i = 0; i < nPkt; i++)
    {
        Ptr<Packet> p = Create<Packet>(pktSize);
        queue->Enqueue(Create<FqCodelQueueDiscTestItem>(p, addr, protocol, true));
    }
}

void
FqCoDelPeekTestMark::Dequeue(Ptr<FqCoDelQueueDisc> queue) 
{
  uint64_t time = Simulator::Now().GetMilliSeconds();
  uint32_t beforeSize = queue->GetCurrentSize().GetValue();
  uint32_t beforeDroppedDequeue = queue->GetStats().GetNDroppedPackets(CoDelQueueDisc::TARGET_EXCEEDED_DROP);
  uint32_t beforeMarked = queue->GetStats().GetNMarkedPackets(CoDelQueueDisc::TARGET_EXCEEDED_MARK);
  Ptr<QueueDiscItem> item = queue->Dequeue();
  m_peeked = false;
  if(item==0)
    NS_LOG_UNCOND("Queue Empty");
  uint32_t afterSize = queue->GetCurrentSize().GetValue();
  uint32_t afterDroppedDequeue = queue->GetStats().GetNDroppedPackets(CoDelQueueDisc::TARGET_EXCEEDED_DROP);
  uint32_t afterMarked = queue->GetStats().GetNMarkedPackets(CoDelQueueDisc::TARGET_EXCEEDED_MARK);
  NS_LOG_UNCOND("At " << time << "ms Dequeue");
  if(item)
    {
      NS_LOG_UNCOND("Packet id Dequeued " << item->GetPacket()->GetUid());
      NS_LOG_UNCOND("Queue Size before - " << beforeSize << " | Packets Dropped before - " << beforeDroppedDequeue << " | Packets marked before - " << beforeMarked);
      NS_LOG_UNCOND("Queue Size after  - " << afterSize << " | Packets Dropped after  - " << afterDroppedDequeue << " | Packets marked after  - " << afterMarked << std::endl);
    }
}

void
FqCoDelPeekTestMark::Peek(Ptr<FqCoDelQueueDisc> queue)
{
  uint64_t time = Simulator::Now().GetMilliSeconds();
  uint32_t beforeSize = queue->GetCurrentSize().GetValue();
  uint32_t beforeDroppedDequeue = queue->GetStats().GetNDroppedPackets(CoDelQueueDisc::TARGET_EXCEEDED_DROP);
  uint32_t beforeMarked = queue->GetStats().GetNMarkedPackets(CoDelQueueDisc::TARGET_EXCEEDED_MARK);
  Ptr<const QueueDiscItem> item = queue->Peek();
  m_peeked = true;
  if(item==0)
    NS_LOG_UNCOND("Queue Empty");
  uint32_t afterSize = queue->GetCurrentSize().GetValue();
  uint32_t afterDroppedDequeue = queue->GetStats().GetNDroppedPackets(CoDelQueueDisc::TARGET_EXCEEDED_DROP);
  uint32_t afterMarked = queue->GetStats().GetNMarkedPackets(CoDelQueueDisc::TARGET_EXCEEDED_MARK);
  NS_LOG_UNCOND("At " << time << "ms Peek");
  if(item)
    {
      NS_LOG_UNCOND("Packet id Peeked " << item->GetPacket()->GetUid());
      NS_LOG_UNCOND("Queue Size before - " << beforeSize << " | Packets Dropped before - " << beforeDroppedDequeue << " | Packets marked before - " << beforeMarked);
      NS_LOG_UNCOND("Queue Size after - " << afterSize << " | Packets Dropped after - " << afterDroppedDequeue << " | Packets marked after - " << afterMarked << std::endl);
    }
}


int main()
{
    NS_LOG_UNCOND("+--------------------------------+");
    NS_LOG_UNCOND("|Test for FqCoDel without Marking|");
    NS_LOG_UNCOND("+--------------------------------+");
    FqCoDelPeekTest f(QueueSizeUnit::PACKETS);
    f.DoRun();
    NS_LOG_UNCOND("+-----------------------------+");
    NS_LOG_UNCOND("|Test for FqCoDel with Marking|");
    NS_LOG_UNCOND("+-----------------------------+");
    FqCoDelPeekTestMark fm(QueueSizeUnit::PACKETS);
    fm.DoRun();   
    return 0;
}