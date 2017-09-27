from bloomfilter import Bloomfilter
from segmenter import segments

class Splunk(object):
    def __init__(self):
        self.bf = Bloomfilter(64)
        self.terms = {}  # Dictionary of term to set of events
        self.events = []
    
    def add_event(self, event):
        """Adds an event to this object"""

        # Generate a unique ID for the event, and save it
        event_id = len(self.events)
        self.events.append(event)

        # Add each term to the bloomfilter, and track the event by each term
        for term in segments(event):
            self.bf.add_value(term)
            if term not in self.terms:
                self.terms[term] = set()
            
            self.terms[term].add(event_id)

    def search_all(self, terms):
        """Search for an AND of all terms"""

        # Start with the universe of all events...
        results = set(range(len(self.events)))

        for term in terms:
            # If a term isn't present at all then we can stop looking
            if not self.bf.might_contain(term):
                return
            if term not in self.terms:
                return

            # Drop events that don't match from our results
            results = results.intersection(self.terms[term])

        for event_id in sorted(results):
            yield self.events[event_id]


    def search_any(self, terms):
        """Search for an OR of all terms"""
        results = set()

        for term in terms:
            # If a term isn't present, we skip it, but don't stop
            if not self.bf.might_contain(term):
                continue
            if term not in self.terms:
                continue

            # Add these events to our results
            results = results.union(self.terms[term])

        for event_id in sorted(results):
            yield self.events[event_id]


def main():
    s = Splunk()
    s.add_event('src_ip = 1.2.3.4')
    s.add_event('src_ip = 5.6.7.8')
    s.add_event('dst_ip = 1.2.3.4')
    
    for event in s.search_all(['src_ip', '5.6']):
        print event
    print '-'
    for event in s.search_any(['src_ip', 'dst_ip']):
        print event


if __name__ ==  '__main__':
    main()
